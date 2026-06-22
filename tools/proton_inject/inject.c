/*
 * sls_proton_inject.so — LD_PRELOAD helper for Proton DLL injection.
 *
 * Hooks Wine's NtCreateUserProcess to inject a Windows DLL into game processes,
 * mirroring OST's RemoteInject approach:
 *   1. NtCreateUserProcess returns with child thread suspended
 *   2. NtAllocateVirtualMemory + NtWriteVirtualMemory → write shellcode + DLL path
 *   3. NtCreateThreadEx → shellcode calls LdrLoadDll (in PE ntdll.dll, avail immediately)
 *   4. Return to caller (which resumes the main thread)
 *
 * Env vars:
 *   PROTON_SLS_INJECT_DLL — Linux path to the Windows DLL (or "appid=path" mapping)
 *
 * Build (64-bit, on Deck):
 *   gcc -shared -fPIC -O2 -Wall -o sls_proton_inject.so inject.c
 */

#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* ── Raw syscall wrappers (safe in clone threads — no glibc state) ─── */

static int raw_open(const char *path, int flags, int mode) {
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}
static ssize_t raw_read(int fd, void *buf, size_t count) {
    return (ssize_t)syscall(SYS_read, fd, buf, count);
}
static int raw_close(int fd) {
    return (int)syscall(SYS_close, fd);
}
static off_t raw_lseek(int fd, off_t offset, int whence) {
    return (off_t)syscall(SYS_lseek, fd, offset, whence);
}
static void *raw_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    return (void *)syscall(SYS_mmap, addr, len, prot, flags, fd, off);
}
static int raw_munmap(void *addr, size_t len) {
    return (int)syscall(SYS_munmap, addr, len);
}
static int raw_mprotect(void *addr, size_t len, int prot) {
    return (int)syscall(SYS_mprotect, addr, len, prot);
}
static void raw_sleep_ms(unsigned ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    syscall(SYS_nanosleep, &ts, NULL);
}
static ssize_t raw_write(int fd, const void *buf, size_t count) {
    return (ssize_t)syscall(SYS_write, fd, buf, count);
}

static unsigned long hex_to_ulong(const char *s)
{
    unsigned long v = 0;
    for (; *s; s++) {
        char c = *s;
        if (c >= '0' && c <= '9')      v = v * 16 + (c - '0');
        else if (c >= 'a' && c <= 'f') v = v * 16 + (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v = v * 16 + (c - 'A' + 10);
        else break;
    }
    return v;
}

/* ── NT type definitions ────────────────────────────────────────────── */

typedef int32_t  NTSTATUS;
typedef uint32_t ULONG;
typedef void    *HANDLE;
typedef size_t   SIZE_T;

#define STATUS_SUCCESS 0
#define MEM_COMMIT     0x1000
#define MEM_RESERVE    0x2000
#define MEM_RELEASE    0x8000
#define PAGE_EXECUTE_READWRITE 0x40
#define THREAD_ALL_ACCESS 0x1FFFFF

/* x86_64 Wine layout offsets used only for filtering child processes. */
#define ProcessBasicInformation 0
#define PBI_PEB_BASE_OFFSET 0x08
#define PEB_PROCESS_PARAMETERS_OFFSET 0x20
#define RTL_USER_PROC_PARAMS_IMAGE_PATH_OFFSET 0x60
#define UNICODE_STRING_LENGTH_OFFSET 0x00
#define UNICODE_STRING_BUFFER_OFFSET 0x08
#define MAX_IMAGE_PATH_CHARS 512

typedef struct { ULONG Length; HANDLE RootDirectory; void *ObjectName;
                 ULONG Attributes; void *SecurityDescriptor; void *SecurityQualityOfService; } OBJECT_ATTRIBUTES;

typedef NTSTATUS (*NtCreateUserProcess_fn)(
    HANDLE *ProcessHandle, HANDLE *ThreadHandle,
    ULONG ProcessDesiredAccess, ULONG ThreadDesiredAccess,
    OBJECT_ATTRIBUTES *ProcessObjectAttributes, OBJECT_ATTRIBUTES *ThreadObjectAttributes,
    ULONG ProcessFlags, ULONG ThreadFlags,
    void *ProcessParameters, void *CreateInfo, void *AttributeList);

typedef NTSTATUS (*NtAllocateVirtualMemory_fn)(HANDLE, void**, ULONG, SIZE_T*, ULONG, ULONG);
typedef NTSTATUS (*NtReadVirtualMemory_fn)(HANDLE, const void*, void*, SIZE_T, SIZE_T*);
typedef NTSTATUS (*NtWriteVirtualMemory_fn)(HANDLE, void*, const void*, SIZE_T, SIZE_T*);
typedef NTSTATUS (*NtCreateThreadEx_fn)(HANDLE*, ULONG, void*, HANDLE, void*, void*, ULONG,
                                        SIZE_T, SIZE_T, SIZE_T, void*);
typedef NTSTATUS (*NtQueryInformationProcess_fn)(HANDLE, int, void*, ULONG, ULONG*);
typedef NTSTATUS (*NtWaitForSingleObject_fn)(HANDLE, int, void*);
typedef NTSTATUS (*NtFreeVirtualMemory_fn)(HANDLE, void**, SIZE_T*, ULONG);
typedef NTSTATUS (*NtClose_fn)(HANDLE);

/* uintptr_t → function pointer cast. find_elf_export returns uintptr_t,
 * so this is integer-to-function-pointer (no -Wpedantic warning). */
#define FPTR_CAST(type, val) ((type)(val))

/* ── Globals ────────────────────────────────────────────────────────── */

static volatile int g_installed = 0;
static uint16_t g_dll_winpath[4096];  /* UTF-16LE: \??\unix/path/to/OnlineFix.dll */

/* NT function pointers (from ntdll.so Unix-side exports) */
static NtAllocateVirtualMemory_fn    pNtAllocateVirtualMemory;
static NtReadVirtualMemory_fn        pNtReadVirtualMemory;
static NtWriteVirtualMemory_fn       pNtWriteVirtualMemory;
static NtCreateThreadEx_fn           pNtCreateThreadEx;
static NtQueryInformationProcess_fn  pNtQueryInformationProcess;
static NtWaitForSingleObject_fn      pNtWaitForSingleObject;
static NtFreeVirtualMemory_fn        pNtFreeVirtualMemory;
static NtClose_fn                    pNtClose;

/* LdrLoadDll RVA from PE ntdll.dll on disk (ImageBase-independent) */
static uint32_t g_LdrLoadDll_rva;

/* Trampoline for original NtCreateUserProcess */
static uintptr_t g_trampoline;

/* ── Debug logging ──────────────────────────────────────────────────── */

static char g_log_path[256];

static void dbg_raw(const char *msg)
{
    if (!g_log_path[0]) {
        const char *home = getenv("HOME");
        if (!home) home = "/tmp";
        int i = 0;
        while (*home && i < 240) g_log_path[i++] = *home++;
        const char *suf = "/.sls_inject.log";
        while (*suf && i < 255) g_log_path[i++] = *suf++;
        g_log_path[i] = '\0';
    }
    int fd = raw_open(g_log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    raw_write(fd, msg, strlen(msg));
    raw_write(fd, "\n", 1);
    raw_close(fd);
}

/* ── /proc/self/maps scanner (malloc-free for clone safety) ─────────── */

/* Find a module's load base by scanning /proc/self/maps.
 * `needle` must appear in the mapping path. Returns first readable segment
 * (lowest address = module base). Works for both ELF .so and PE .dll. */
#define MAPS_BUF_SIZE (256 * 1024)
#define FALLBACK_PAGE_SIZE 4096UL

static size_t get_page_size(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    return page_size > 0 ? (size_t)page_size : FALLBACK_PAGE_SIZE;
}

static uintptr_t align_page_down(uintptr_t address, size_t page_size)
{
    return address & ~((uintptr_t)page_size - 1);
}

static size_t page_span_len(uintptr_t address, size_t len, size_t page_size)
{
    uintptr_t start = align_page_down(address, page_size);
    uintptr_t end = align_page_down(address + len - 1, page_size) + page_size;
    return (size_t)(end - start);
}

static unsigned long find_module_base(const char *needle)
{
    int fd = raw_open("/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return 0;
    char *buf = raw_mmap(NULL, MAPS_BUF_SIZE, PROT_READ|PROT_WRITE,
                         MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { raw_close(fd); return 0; }
    ssize_t total = 0;
    while (total < MAPS_BUF_SIZE - 1) {
        ssize_t r = raw_read(fd, buf + total, MAPS_BUF_SIZE - 1 - total);
        if (r <= 0) break;
        total += r;
    }
    raw_close(fd);
    ssize_t n = total;
    if (n <= 0) { raw_munmap(buf, MAPS_BUF_SIZE); return 0; }
    buf[n] = '\0';

    unsigned long result = 0;
    char *line = buf;
    while (*line) {
        char *eol = strchr(line, '\n');
        if (eol) *eol = '\0';
        if (strstr(line, needle)) {
            result = hex_to_ulong(line);
            break;
        }
        if (!eol) break;
        line = eol + 1;
    }
    raw_munmap(buf, MAPS_BUF_SIZE);
    return result;
}

/* Find an export in an ELF .so by reading the file directly.
 * path: extracted from /proc/self/maps (may contain spaces).
 * If out_path is non-NULL, copies the discovered file path into it. */
static uintptr_t find_elf_export(unsigned long base, const char *maps_needle, const char *sym_name,
                                  char *out_path, size_t out_path_sz)
{
    /* Re-scan maps to get the full path */
    int mfd = raw_open("/proc/self/maps", O_RDONLY, 0);
    if (mfd < 0) return 0;
    char *mbuf = raw_mmap(NULL, MAPS_BUF_SIZE, PROT_READ|PROT_WRITE,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mbuf == MAP_FAILED) { raw_close(mfd); return 0; }
    ssize_t mn = 0;
    while (mn < MAPS_BUF_SIZE - 1) {
        ssize_t r = raw_read(mfd, mbuf + mn, MAPS_BUF_SIZE - 1 - mn);
        if (r <= 0) break;
        mn += r;
    }
    raw_close(mfd);
    if (mn <= 0) { raw_munmap(mbuf, MAPS_BUF_SIZE); return 0; }
    mbuf[mn] = '\0';

    char filepath[512] = {0};
    char *line = mbuf;
    while (*line) {
        char *eol = strchr(line, '\n');
        if (eol) *eol = '\0';
        if (strstr(line, maps_needle) && strstr(line, " r--p ")) {
            char *p = line; int fields = 0;
            while (*p && fields < 5) { while (*p == ' ') p++; while (*p && *p != ' ' && *p != '\n') p++; fields++; }
            while (*p == ' ') p++;
            if (*p == '/') {
                strncpy(filepath, p, sizeof(filepath) - 1);
                size_t pl = strlen(filepath);
                while (pl > 0 && (filepath[pl-1] == '\n' || filepath[pl-1] == '\r'))
                    filepath[--pl] = '\0';
            }
            break;
        }
        if (!eol) break;
        line = eol + 1;
    }
    raw_munmap(mbuf, MAPS_BUF_SIZE);
    if (!filepath[0]) return 0;

    if (out_path && out_path_sz > 0) {
        size_t cplen = strlen(filepath);
        if (cplen >= out_path_sz) cplen = out_path_sz - 1;
        memcpy(out_path, filepath, cplen);
        out_path[cplen] = '\0';
    }

    int fd = raw_open(filepath, O_RDONLY, 0);
    if (fd < 0) return 0;
    uintptr_t result = 0;

#ifdef __x86_64__
    Elf64_Ehdr eh;
    if (raw_read(fd, &eh, sizeof(eh)) != sizeof(eh)) { raw_close(fd); return 0; }
    size_t sh_sz = eh.e_shnum * sizeof(Elf64_Shdr);
    Elf64_Shdr *sh = raw_mmap(NULL, sh_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (sh == MAP_FAILED) { raw_close(fd); return 0; }
    raw_lseek(fd, eh.e_shoff, SEEK_SET);
    raw_read(fd, sh, sh_sz);
    for (int i = 0; i < eh.e_shnum; i++) {
        if (sh[i].sh_type != SHT_DYNSYM) continue;
        size_t sym_sz = sh[i].sh_size, str_sz = sh[sh[i].sh_link].sh_size;
        void *buf = raw_mmap(NULL, sym_sz + str_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (buf == MAP_FAILED) break;
        Elf64_Sym *sy = buf; char *st = (char*)buf + sym_sz;
        int ns = sym_sz / sizeof(Elf64_Sym);
        raw_lseek(fd, sh[i].sh_offset, SEEK_SET); raw_read(fd, sy, sym_sz);
        raw_lseek(fd, sh[sh[i].sh_link].sh_offset, SEEK_SET); raw_read(fd, st, str_sz);
        for (int j = 0; j < ns; j++) {
            if (sy[j].st_name && strcmp(st + sy[j].st_name, sym_name) == 0) {
                result = base + sy[j].st_value;
                break;
            }
        }
        raw_munmap(buf, sym_sz + str_sz);
        break;
    }
    raw_munmap(sh, sh_sz);
#endif
    raw_close(fd);
    return result;
}

/* ── PE file parser (from disk, not memory) ────────────────────────── */

/* Convert an RVA to a file offset using PE section headers.
 * sec: array of section headers, nsec: number of sections.
 * Returns (uint32_t)-1 on failure. */
static uint32_t rva_to_offset(const uint8_t *sec, int nsec, uint32_t rva)
{
    for (int i = 0; i < nsec; i++) {
        const uint8_t *s = sec + i * 40;
        uint32_t vaddr = *(uint32_t *)(s + 12);
        uint32_t vsize = *(uint32_t *)(s + 8);
        uint32_t rawoff = *(uint32_t *)(s + 20);
        if (rva >= vaddr && rva < vaddr + vsize)
            return rawoff + (rva - vaddr);
    }
    return (uint32_t)-1;
}

/* Find a PE export RVA by parsing the PE file on disk.
 * Returns the RVA (not absolute address) — caller adds the actual runtime base. */
static uint32_t find_pe_export_rva(const char *filepath, const char *func_name)
{
    int fd = raw_open(filepath, O_RDONLY, 0);
    if (fd < 0) return 0;

    /* DOS header */
    uint8_t dos[64];
    if (raw_read(fd, dos, 64) != 64) { raw_close(fd); return 0; }
    if (dos[0] != 'M' || dos[1] != 'Z') { raw_close(fd); return 0; }
    uint32_t pe_off = *(uint32_t *)(dos + 0x3C);

    /* PE signature + COFF header (24 bytes) + optional header */
    raw_lseek(fd, pe_off, SEEK_SET);
    uint8_t pe_hdr[0x200];
    ssize_t pe_rd = raw_read(fd, pe_hdr, sizeof(pe_hdr));
    if (pe_rd < 0x88 + 8) { raw_close(fd); return 0; }
    if (pe_hdr[0] != 'P' || pe_hdr[1] != 'E') { raw_close(fd); return 0; }

    uint16_t nsections = *(uint16_t *)(pe_hdr + 6);
    uint16_t opt_hdr_size = *(uint16_t *)(pe_hdr + 20);

    uint16_t magic = *(uint16_t *)(pe_hdr + 24);
    uint32_t export_rva, export_size;
    if (magic == 0x20B) {
        export_rva  = *(uint32_t *)(pe_hdr + 24 + 0x70);
        export_size = *(uint32_t *)(pe_hdr + 24 + 0x74);
    } else if (magic == 0x10B) {
        export_rva  = *(uint32_t *)(pe_hdr + 24 + 0x60);
        export_size = *(uint32_t *)(pe_hdr + 24 + 0x64);
    } else {
        raw_close(fd); return 0;
    }

    if (!export_rva || !export_size) { raw_close(fd); return 0; }

    size_t sec_off = pe_off + 24 + opt_hdr_size;
    raw_lseek(fd, sec_off, SEEK_SET);
    size_t sec_sz = nsections * 40;
    uint8_t *sec = raw_mmap(NULL, sec_sz, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (sec == MAP_FAILED) { raw_close(fd); return 0; }
    raw_read(fd, sec, sec_sz);

    uint32_t exp_foff = rva_to_offset(sec, nsections, export_rva);
    if (exp_foff == (uint32_t)-1) { raw_munmap(sec, sec_sz); raw_close(fd); return 0; }

    raw_lseek(fd, exp_foff, SEEK_SET);
    uint8_t expdir[40];
    if (raw_read(fd, expdir, 40) != 40) { raw_munmap(sec, sec_sz); raw_close(fd); return 0; }

    uint32_t num_funcs = *(uint32_t *)(expdir + 0x14);
    uint32_t num_names = *(uint32_t *)(expdir + 0x18);
    uint32_t addr_rva  = *(uint32_t *)(expdir + 0x1C);
    uint32_t name_rva  = *(uint32_t *)(expdir + 0x20);
    uint32_t ord_rva   = *(uint32_t *)(expdir + 0x24);
    if (!num_funcs || !num_names) { raw_munmap(sec, sec_sz); raw_close(fd); return 0; }

    size_t addr_sz = (size_t)num_funcs * 4;
    size_t name_sz = (size_t)num_names * 4;
    size_t ord_sz = (size_t)num_names * 2;
    size_t tbl_sz = addr_sz + name_sz + ord_sz;
    void *tbl = raw_mmap(NULL, tbl_sz, PROT_READ|PROT_WRITE,
                         MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (tbl == MAP_FAILED) { raw_munmap(sec, sec_sz); raw_close(fd); return 0; }

    uint32_t *addrs = tbl;
    uint32_t *names = (uint32_t *)((char*)tbl + addr_sz);
    uint16_t *ords  = (uint16_t *)((char*)tbl + addr_sz + name_sz);

    uint32_t fo;
    fo = rva_to_offset(sec, nsections, addr_rva);
    if (fo != (uint32_t)-1) { raw_lseek(fd, fo, SEEK_SET); raw_read(fd, addrs, addr_sz); }
    fo = rva_to_offset(sec, nsections, name_rva);
    if (fo != (uint32_t)-1) { raw_lseek(fd, fo, SEEK_SET); raw_read(fd, names, name_sz); }
    fo = rva_to_offset(sec, nsections, ord_rva);
    if (fo != (uint32_t)-1) { raw_lseek(fd, fo, SEEK_SET); raw_read(fd, ords, ord_sz); }

    uint32_t result = 0;
    char name_buf[128];
    for (uint32_t i = 0; i < num_names; i++) {
        uint32_t nfo = rva_to_offset(sec, nsections, names[i]);
        if (nfo == (uint32_t)-1) continue;
        raw_lseek(fd, nfo, SEEK_SET);
        ssize_t nr = raw_read(fd, name_buf, sizeof(name_buf) - 1);
        if (nr <= 0) continue;
        name_buf[nr] = '\0';
        if (strcmp(name_buf, func_name) == 0) {
            if (ords[i] >= num_funcs)
                break;
            uint32_t fn_rva = addrs[ords[i]];
            if (fn_rva >= export_rva && fn_rva < export_rva + export_size)
                break; /* forwarded */
            result = fn_rva;
            break;
        }
    }

    raw_munmap(tbl, tbl_sz);
    raw_munmap(sec, sec_sz);
    raw_close(fd);
    return result;
}

/* ── Detour hook ────────────────────────────────────────────────────── */

static int detour_install(uintptr_t target, uintptr_t hook, uintptr_t *out_trampoline, size_t stolen)
{
    const size_t page_size = get_page_size();
    void *tramp = raw_mmap(NULL, page_size, PROT_READ|PROT_WRITE|PROT_EXEC,
                           MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) return -1;

    uint8_t *t = tramp;
    memcpy(t, (void *)target, stolen);
    t[stolen] = 0x48; t[stolen+1] = 0xB8;
    *(uint64_t *)(t + stolen + 2) = target + stolen;
    t[stolen+10] = 0xFF; t[stolen+11] = 0xE0;

    uintptr_t page = align_page_down(target, page_size);
    size_t patch_span = page_span_len(target, stolen, page_size);
    if (raw_mprotect((void *)page, patch_span, PROT_READ|PROT_WRITE|PROT_EXEC) != 0) {
        raw_munmap(tramp, page_size);
        return -1;
    }

    uint8_t *p = (uint8_t *)target;
    p[0] = 0x48; p[1] = 0xB8;
    *(uint64_t *)(p + 2) = hook;
    p[10] = 0xFF; p[11] = 0xE0;
    for (size_t i = 12; i < stolen; i++) p[i] = 0x90;

    raw_mprotect((void *)page, patch_span, PROT_READ|PROT_EXEC);

    *out_trampoline = (uintptr_t)tramp;
    return 0;
}

/* ── Remote inject via LdrLoadDll shellcode ─────────────────────────── */

/*
 * Remote memory layout (relative to allocBase):
 *   +0x000  uint16_t dll_path[]           UTF-16LE DLL path
 *   +0x400  UNICODE_STRING {Length, MaxLen, pad, Buffer}
 *   +0x410  PVOID hModule                output for LdrLoadDll
 *   +0x418  NTSTATUS result              LdrLoadDll return value
 *   +0x430  shellcode:
 *             sub  rsp, 0x28
 *             xor  ecx, ecx               SearchPath = NULL
 *             xor  edx, edx               DllCharacteristics = NULL
 *             mov  r8,  <&UNICODE_STRING>  DllName
 *             mov  r9,  <&hModule>         BaseAddress out
 *             mov  rax, <LdrLoadDll>
 *             call rax
 *             add  rsp, 0x28
 *             ret
 */
#define REMOTE_USTR_OFF   0x400
#define REMOTE_HMOD_OFF   0x410
#define REMOTE_STAT_OFF   0x418
#define REMOTE_CODE_OFF   0x430
#define REMOTE_TOTAL_SIZE 0x600

/* Cached PE ntdll.dll base address from a sibling Wine process.
 * All Wine processes in the same session map PE ntdll.dll at the same address. */
static uint64_t g_pe_ntdll_base;

/* Scan /proc for any Wine process that has PE ntdll.dll mapped,
 * cache the base address for all future injections. */
static void resolve_pe_ntdll_base_from_siblings(const char *pe_needle)
{
    if (g_pe_ntdll_base) return;

    /* Scan /proc for directories (PIDs) */
    int dfd = raw_open("/proc", O_RDONLY | O_DIRECTORY, 0);
    if (dfd < 0) return;

    /* Read /proc entries — use getdents64 syscall */
    char dirbuf[4096];
    for (;;) {
        long nread = syscall(SYS_getdents64, dfd, dirbuf, sizeof(dirbuf));
        if (nread <= 0) break;
        for (long pos = 0; pos < nread; ) {
            struct linux_dirent64 {
                uint64_t d_ino;
                int64_t d_off;
                unsigned short d_reclen;
                unsigned char d_type;
                char d_name[];
            } *d = (void *)(dirbuf + pos);
            pos += d->d_reclen;

            /* Only numeric directories (PIDs) */
            if (d->d_name[0] < '0' || d->d_name[0] > '9') continue;

            /* Build /proc/PID/maps path */
            char maps_path[64];
            int len = 0;
            const char *prefix = "/proc/";
            while (*prefix) maps_path[len++] = *prefix++;
            char *p = d->d_name;
            while (*p) maps_path[len++] = *p++;
            const char *suffix = "/maps";
            while (*suffix) maps_path[len++] = *suffix++;
            maps_path[len] = '\0';

            int mfd = raw_open(maps_path, O_RDONLY, 0);
            if (mfd < 0) continue;
            char *mbuf = raw_mmap(NULL, MAPS_BUF_SIZE, PROT_READ|PROT_WRITE,
                                  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if (mbuf == MAP_FAILED) { raw_close(mfd); continue; }
            ssize_t total = 0;
            while (total < MAPS_BUF_SIZE - 1) {
                ssize_t r = raw_read(mfd, mbuf + total, MAPS_BUF_SIZE - 1 - total);
                if (r <= 0) break;
                total += r;
            }
            raw_close(mfd);
            if (total <= 0) { raw_munmap(mbuf, MAPS_BUF_SIZE); continue; }
            mbuf[total] = '\0';

            /* Search for pe_needle in this process's maps */
            char *line = mbuf;
            while (*line) {
                char *eol = strchr(line, '\n');
                if (eol) *eol = '\0';
                if (strstr(line, pe_needle)) {
                    g_pe_ntdll_base = hex_to_ulong(line);
                    if (eol) *eol = '\n';
                    break;
                }
                if (!eol) break;
                line = eol + 1;
            }
            raw_munmap(mbuf, MAPS_BUF_SIZE);
            if (g_pe_ntdll_base) break;
        }
        if (g_pe_ntdll_base) break;
    }
    raw_close(dfd);
}

static size_t u16len(const uint16_t *s) { size_t n = 0; while (s[n]) n++; return n; }

static int inject_dll(HANDLE hProcess, const uint16_t *dllPath)
{
    if (!g_pe_ntdll_base) {
        dbg_raw("inject: no PE ntdll base cached");
        return -1;
    }
    uint64_t ldr_addr = g_pe_ntdll_base + g_LdrLoadDll_rva;

    uint8_t local[REMOTE_TOTAL_SIZE];
    memset(local, 0, sizeof(local));

    size_t pathLen = u16len(dllPath);
    if ((pathLen + 1) * sizeof(uint16_t) > REMOTE_USTR_OFF)
        return -1;
    memcpy(local, dllPath, (pathLen + 1) * sizeof(uint16_t));

    void *remoteMem = NULL;
    SIZE_T regionSize = REMOTE_TOTAL_SIZE;
    NTSTATUS st = pNtAllocateVirtualMemory(hProcess, &remoteMem, 0,
                                            &regionSize, MEM_COMMIT | MEM_RESERVE,
                                            PAGE_EXECUTE_READWRITE);
    if (st != STATUS_SUCCESS || !remoteMem) {
        dbg_raw("inject: NtAllocateVirtualMemory failed");
        return -1;
    }

    uintptr_t base = (uintptr_t)remoteMem;

    /* UNICODE_STRING { Length, MaximumLength, (pad), Buffer } — sizes in bytes (UTF-16) */
    *(uint16_t *)(local + REMOTE_USTR_OFF + 0) = (uint16_t)(pathLen * 2);
    *(uint16_t *)(local + REMOTE_USTR_OFF + 2) = (uint16_t)((pathLen + 1) * 2);
    *(uint64_t *)(local + REMOTE_USTR_OFF + 8) = base;  /* Buffer → remote dll_path */

    /* Shellcode */
    uint8_t *sc = local + REMOTE_CODE_OFF;
    int off = 0;
    sc[off++] = 0x48; sc[off++] = 0x83; sc[off++] = 0xEC; sc[off++] = 0x28; /* sub rsp,0x28 */
    sc[off++] = 0x48; sc[off++] = 0x31; sc[off++] = 0xC9;                   /* xor rcx,rcx  */
    sc[off++] = 0x48; sc[off++] = 0x31; sc[off++] = 0xD2;                   /* xor rdx,rdx  */
    sc[off++] = 0x49; sc[off++] = 0xB8;                                     /* movabs r8    */
    *(uint64_t *)(sc + off) = base + REMOTE_USTR_OFF; off += 8;
    sc[off++] = 0x49; sc[off++] = 0xB9;                                     /* movabs r9    */
    *(uint64_t *)(sc + off) = base + REMOTE_HMOD_OFF; off += 8;
    sc[off++] = 0x48; sc[off++] = 0xB8;                                     /* movabs rax   */
    *(uint64_t *)(sc + off) = ldr_addr; off += 8;
    sc[off++] = 0xFF; sc[off++] = 0xD0;                                     /* call rax     */
    /* Store NTSTATUS return value at REMOTE_STAT_OFF */
    sc[off++] = 0x48; sc[off++] = 0xB9;                                     /* movabs rcx   */
    *(uint64_t *)(sc + off) = base + REMOTE_STAT_OFF; off += 8;
    sc[off++] = 0x89; sc[off++] = 0x01;                                     /* mov [rcx],eax */
    sc[off++] = 0x48; sc[off++] = 0x83; sc[off++] = 0xC4; sc[off++] = 0x28; /* add rsp,0x28 */
    sc[off++] = 0xC3;                                                        /* ret          */

    /* Mark status as sentinel before injection */
    *(uint32_t *)(local + REMOTE_STAT_OFF) = 0xDEADBEEF;

    st = pNtWriteVirtualMemory(hProcess, remoteMem, local, REMOTE_TOTAL_SIZE, NULL);
    if (st != STATUS_SUCCESS) {
        dbg_raw("inject: NtWriteVirtualMemory failed");
        pNtFreeVirtualMemory(hProcess, &remoteMem, &regionSize, MEM_RELEASE);
        return -1;
    }

    HANDLE hRemoteThread = NULL;
    st = pNtCreateThreadEx(&hRemoteThread, THREAD_ALL_ACCESS, NULL, hProcess,
                           (void *)(base + REMOTE_CODE_OFF), NULL,
                           0, 0, 0, 0, NULL);
    if (st != STATUS_SUCCESS || !hRemoteThread) {
        dbg_raw("inject: NtCreateThreadEx failed");
        pNtFreeVirtualMemory(hProcess, &remoteMem, &regionSize, MEM_RELEASE);
        return -1;
    }

    int64_t timeout = -50000000LL; /* 5s relative */
    pNtWaitForSingleObject(hRemoteThread, 0, &timeout);
    pNtClose(hRemoteThread);

    /* Read back LdrLoadDll NTSTATUS from remote memory */
    uint32_t remote_status = 0xDEADBEEF;
    if (pNtReadVirtualMemory)
        pNtReadVirtualMemory(hProcess, (const void *)(base + REMOTE_STAT_OFF),
                              &remote_status, 4, NULL);
    pNtFreeVirtualMemory(hProcess, &remoteMem, &regionSize, MEM_RELEASE);

    if (remote_status == 0) {
        dbg_raw("inject: OK");
    } else {
        char msg[48] = "inject: NTSTATUS 0x";
        char *p = msg + 19;
        for (int i = 28; i >= 0; i -= 4) {
            int d = (remote_status >> i) & 0xF;
            *p++ = d < 10 ? '0' + d : 'a' + d - 10;
        }
        *p = '\0';
        dbg_raw(msg);
    }
    return 0;
}

/* ── NtCreateUserProcess hook ───────────────────────────────────────── */

/* Case-insensitive UTF-16 substring check for "\windows\" */
static int u16_contains_windows(const uint16_t *s, int nchars)
{
    static const uint16_t pat[] = { '\\','w','i','n','d','o','w','s','\\' };
    if (nchars < 9) return 0;
    for (int i = 0; i <= nchars - 9; i++) {
        int ok = 1;
        for (int j = 0; j < 9; j++) {
            uint16_t a = s[i + j], b = pat[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (a != b) { ok = 0; break; }
        }
        if (ok) return 1;
    }
    return 0;
}

/* Read child process's ImagePathName from PEB → ProcessParameters.
 * Returns 1 if the process should be injected (not a system process). */
static int should_inject_child(HANDLE hProcess)
{
    if (!pNtQueryInformationProcess || !pNtReadVirtualMemory)
        return 1; /* can't filter — inject anyway */

    uint8_t pbi[48] = {0};
    ULONG retlen = 0;
    if (pNtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi, sizeof(pbi), &retlen) != STATUS_SUCCESS)
        return 1;

    uint64_t peb_addr = *(uint64_t *)(pbi + PBI_PEB_BASE_OFFSET);
    if (!peb_addr) return 1;

    /* PEB.ProcessParameters is set before the child thread starts. */
    uint64_t pp_addr = 0;
    if (pNtReadVirtualMemory(hProcess, (const void *)(peb_addr + PEB_PROCESS_PARAMETERS_OFFSET), &pp_addr, sizeof(pp_addr), NULL) != STATUS_SUCCESS || !pp_addr)
        return 1;

    /* RTL_USER_PROCESS_PARAMETERS.ImagePathName is a UNICODE_STRING. */
    uint16_t img_len = 0;  /* bytes */
    uint64_t img_buf = 0;
    pNtReadVirtualMemory(hProcess, (const void *)(pp_addr + RTL_USER_PROC_PARAMS_IMAGE_PATH_OFFSET + UNICODE_STRING_LENGTH_OFFSET), &img_len, sizeof(img_len), NULL);
    pNtReadVirtualMemory(hProcess, (const void *)(pp_addr + RTL_USER_PROC_PARAMS_IMAGE_PATH_OFFSET + UNICODE_STRING_BUFFER_OFFSET), &img_buf, sizeof(img_buf), NULL);
    if (!img_buf || img_len < 10) return 1;

    int nchars = img_len / 2;
    if (nchars > MAX_IMAGE_PATH_CHARS) nchars = MAX_IMAGE_PATH_CHARS;
    uint16_t path_buf[MAX_IMAGE_PATH_CHARS];
    if (pNtReadVirtualMemory(hProcess, (const void *)img_buf, path_buf, nchars * 2, NULL) != STATUS_SUCCESS)
        return 1;

    if (u16_contains_windows(path_buf, nchars))
        return 0; /* system process — skip */

    return 1;
}

static NTSTATUS hook_NtCreateUserProcess(
    HANDLE *ProcessHandle, HANDLE *ThreadHandle,
    ULONG ProcessDesiredAccess, ULONG ThreadDesiredAccess,
    OBJECT_ATTRIBUTES *ProcessObjectAttributes, OBJECT_ATTRIBUTES *ThreadObjectAttributes,
    ULONG ProcessFlags, ULONG ThreadFlags,
    void *ProcessParameters, void *CreateInfo, void *AttributeList)
{
    NtCreateUserProcess_fn orig = FPTR_CAST(NtCreateUserProcess_fn, g_trampoline);

    NTSTATUS st = orig(ProcessHandle, ThreadHandle,
                       ProcessDesiredAccess, ThreadDesiredAccess,
                       ProcessObjectAttributes, ThreadObjectAttributes,
                       ProcessFlags, ThreadFlags,
                       ProcessParameters, CreateInfo, AttributeList);

    if (st == STATUS_SUCCESS && ProcessHandle && *ProcessHandle &&
        g_LdrLoadDll_rva && g_dll_winpath[0])
    {
        if (!g_pe_ntdll_base)
            resolve_pe_ntdll_base_from_siblings("x86_64-windows/ntdll.dll");

        if (should_inject_child(*ProcessHandle)) {
            dbg_raw("NtCreateUserProcess: injecting");
            inject_dll(*ProcessHandle, g_dll_winpath);
        }
    }

    return st;
}

/* ── Resolve env var ────────────────────────────────────────────────── */

static int resolve_dll_path(uint16_t *out, size_t out_chars)
{
    const char *val = getenv("PROTON_SLS_INJECT_DLL");
    if (!val || !val[0]) return 0;

    const char *path = val;
    if (val[0] != '/') {
        const char *app_id = getenv("SteamAppId");
        if (!app_id || !app_id[0]) return 0;
        size_t id_len = strlen(app_id);
        const char *p = val;
        path = NULL;
        while (*p) {
            if (strncmp(p, app_id, id_len) == 0 && p[id_len] == '=') {
                path = p + id_len + 1;
                break;
            }
            const char *next = strchr(p, ',');
            if (!next) break;
            p = next + 1;
        }
        if (!path) return 0;
    }

    /* Convert Linux path → Wine NT path (UTF-16LE): \??\unix/absolute/path
     * Uses uint16_t (2 bytes per char) matching Windows WCHAR, not Linux
     * wchar_t (4 bytes). This bypasses DOS device resolution (Z: drive). */
    uint16_t *wp = out;
    static const char prefix[] = "\\??\\unix";
    for (int i = 0; prefix[i]; i++) *wp++ = (uint16_t)(unsigned char)prefix[i];
    const char *end = strchr(path, ',');
    for (const char *p = path; *p && p != end && wp < out + out_chars - 1; p++)
        *wp++ = (uint16_t)(unsigned char)*p;
    *wp = 0;
    return 1;
}

/* ── Init (called from clone thread when ntdll.so is ready) ─────────── */

static void try_install(void)
{
    if (g_installed) return;

    /* Find Unix-side ntdll.so exports */
    unsigned long ntdll_base = find_module_base("unix/ntdll.so");
    if (!ntdll_base) return;

    char ntdll_unix_path[512] = {0};
    uintptr_t pNtCreateUserProcess = find_elf_export(ntdll_base, "unix/ntdll.so", "NtCreateUserProcess",
                                                     ntdll_unix_path, sizeof(ntdll_unix_path));
    dbg_raw("found ntdll.so");
#define RESOLVE(var, type, name) var = FPTR_CAST(type, find_elf_export(ntdll_base, "unix/ntdll.so", name, NULL, 0))
    RESOLVE(pNtAllocateVirtualMemory,   NtAllocateVirtualMemory_fn,   "NtAllocateVirtualMemory");
    RESOLVE(pNtReadVirtualMemory,       NtReadVirtualMemory_fn,       "NtReadVirtualMemory");
    RESOLVE(pNtWriteVirtualMemory,      NtWriteVirtualMemory_fn,      "NtWriteVirtualMemory");
    RESOLVE(pNtCreateThreadEx,          NtCreateThreadEx_fn,          "NtCreateThreadEx");
    RESOLVE(pNtQueryInformationProcess, NtQueryInformationProcess_fn, "NtQueryInformationProcess");
    RESOLVE(pNtWaitForSingleObject,     NtWaitForSingleObject_fn,     "NtWaitForSingleObject");
    RESOLVE(pNtFreeVirtualMemory,       NtFreeVirtualMemory_fn,       "NtFreeVirtualMemory");
    RESOLVE(pNtClose,                   NtClose_fn,                   "NtClose");
#undef RESOLVE

    if (!pNtCreateUserProcess || !pNtAllocateVirtualMemory ||
        !pNtWriteVirtualMemory || !pNtCreateThreadEx ||
        !pNtWaitForSingleObject || !pNtFreeVirtualMemory || !pNtClose)
        return;

    /* Derive PE ntdll.dll path from Unix ntdll.so path:
     * .../lib/wine/x86_64-unix/ntdll.so → .../lib/wine/x86_64-windows/ntdll.dll
     * Wine maps PE modules at their preferred ImageBase, so we parse the PE file
     * on disk to get ImageBase + LdrLoadDll RVA. The parent (wine64-preloader)
     * never maps PE modules itself — only child processes do. */
    char pe_path[512] = {0};
    char *unix_dir = strstr(ntdll_unix_path, "x86_64-unix/ntdll.so");
    if (!unix_dir) { dbg_raw("cant derive pe path"); return; }
    size_t prefix_len = unix_dir - ntdll_unix_path;
    memcpy(pe_path, ntdll_unix_path, prefix_len);
    strcpy(pe_path + prefix_len, "x86_64-windows/ntdll.dll");

    g_LdrLoadDll_rva = find_pe_export_rva(pe_path, "LdrLoadDll");
    if (!g_LdrLoadDll_rva) { dbg_raw("no LdrLoadDll in pe file"); return; }
    dbg_raw("found LdrLoadDll RVA");

    /* Detour needs 14 bytes (movabs rax,imm64; jmp rax). Compute how many
     * complete instructions to steal by decoding modrm-aware lengths. */
    uint8_t *tgt = (uint8_t *)pNtCreateUserProcess;
    size_t stolen = 0;
    for (int i = 0; i < 12 && stolen < 14; i++) {
        uint8_t *p = tgt + stolen;
        int len = 0;

        /* endbr64 (CET): F3 0F 1E FA */
        if (p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && p[3] == 0xFA) { len = 4; }
        /* nop */
        else if (p[0] == 0x90) { len = 1; }
        /* push/pop r (50-5F) */
        else if (p[0] >= 0x50 && p[0] <= 0x5F) { len = 1; }
        /* REX.B push/pop r8-r15 (41 50-5F) */
        else if (p[0] == 0x41 && p[1] >= 0x50 && p[1] <= 0x5F) { len = 2; }
        /* SSE with 66 0F prefix (pxor, movdqa, etc.) — modrm-based */
        else if (p[0] == 0x66 && p[1] == 0x0F) {
            uint8_t modrm = p[3];
            uint8_t mod = modrm >> 6, rm = modrm & 7;
            len = 4; /* 66 0F op modrm */
            if (rm == 4 && mod != 3) len++;
            if (mod == 0 && rm == 5) break; /* RIP-relative — unsafe */
            else if (mod == 1) len += 1;
            else if (mod == 2) len += 4;
        }
        /* REX.W instructions (48/49 prefix) — decode modrm */
        else if ((p[0] & 0xFE) == 0x48) {
            uint8_t op = p[1];
            if (op == 0x83 || op == 0xC7 || op == 0x81 ||
                op == 0x89 || op == 0x8B || op == 0x8D || op == 0x85 || op == 0x3B) {
                /* modrm-based: mov/lea/test/cmp/sub/and/or */
            } else {
                break;
            }
            uint8_t modrm = p[2];
            uint8_t mod = modrm >> 6, rm = modrm & 7;
            len = 3;
            if (rm == 4 && mod != 3) len++; /* SIB */
            if (mod == 0 && rm == 5) break; /* RIP-relative — unsafe */
            else if (mod == 1) len += 1;
            else if (mod == 2) len += 4;
            if (op == 0x83) len += 1;
            else if (op == 0x81 || op == 0xC7) len += 4;
        }
        else { break; }

        if (len == 0) break;
        stolen += len;
    }
    if (stolen < 14) { dbg_raw("prologue too short"); return; }

    if (detour_install(pNtCreateUserProcess, (uintptr_t)hook_NtCreateUserProcess,
                       &g_trampoline, stolen) != 0)
        return;

    g_installed = 1;
    /* dbg is unsafe in clone thread — signal success via g_installed */
}

/* ── Clone-based poll thread ────────────────────────────────────────── */

#define POLL_STACK_SIZE (2 * 1024 * 1024)

static volatile int g_poll_done = 0;

static int poll_fn(void *arg)
{
    (void)arg;
    for (int i = 0; i < 6000 && !g_installed; i++) {
        raw_sleep_ms(5);
        try_install();
    }
    if (!g_installed) dbg_raw("poll: gave up");
    g_poll_done = 1;
    syscall(SYS_exit, 0);
    return 0;
}

__attribute__((constructor))
static void sls_proton_inject_init(void)
{
    dbg_raw("ctor");
    if (!resolve_dll_path(g_dll_winpath, sizeof(g_dll_winpath) / sizeof(uint16_t))) {
        dbg_raw("resolve failed");
        return;
    }
    dbg_raw("resolved OK");

    try_install();
    if (g_installed) {
        dbg_raw("ACTIVE (immediate)");
        return;
    }

    void *stack = raw_mmap(NULL, POLL_STACK_SIZE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) return;

    clone(poll_fn, (char *)stack + POLL_STACK_SIZE,
          CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD, NULL);

    /* Wait briefly for the poll thread — if it succeeds quickly we can log it.
     * Don't block too long or ld.so can't finish loading. */
    for (int i = 0; i < 20 && !g_installed && !g_poll_done; i++)
        raw_sleep_ms(50); /* 50ms × 20 = 1s max */

    if (g_installed)
        dbg_raw("ACTIVE (poll)");
    else
        dbg_raw("poll: waiting for modules");
}
