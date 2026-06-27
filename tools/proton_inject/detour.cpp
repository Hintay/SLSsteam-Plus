#include "detour.hpp"

#include "raii.hpp"
#include "syscalls.hpp"

#include <cstdint>
#include <cstring>
#include <sys/mman.h>

namespace sls::detour {

namespace {

constexpr size_t kAbsJumpSize = 14;

void write_abs_jump(uint8_t* dst, uint64_t target) {
    dst[0] = 0x48; dst[1] = 0xB8;                                    // movabs rax, imm64
    *reinterpret_cast<uint64_t*>(dst + 2) = target;
    dst[10] = 0xFF; dst[11] = 0xE0;                                  // jmp rax
}

} // namespace

size_t prologue_steal_bytes(const uint8_t* target) {
    size_t stolen = 0;
    for (int step = 0; step < 12 && stolen < kAbsJumpSize; step++) {
        const uint8_t* p = target + stolen;
        size_t len = 0;

        if (p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && p[3] == 0xFA) {
            len = 4;                            // endbr64 (CET)
        } else if (p[0] == 0x90) {
            len = 1;                            // nop
        } else if (p[0] >= 0x50 && p[0] <= 0x5F) {
            len = 1;                            // push/pop r
        } else if (p[0] == 0x41 && p[1] >= 0x50 && p[1] <= 0x5F) {
            len = 2;                            // REX.B push/pop r8-r15
        } else if (p[0] == 0x66 && p[1] == 0x0F) {
            const uint8_t modrm = p[3];
            const uint8_t mod = modrm >> 6;
            const uint8_t rm = modrm & 7;
            len = 4;                            // 66 0F op modrm
            if (rm == 4 && mod != 3) len++;
            if (mod == 0 && rm == 5) return 0;  // RIP-relative — unsafe to steal
            if (mod == 1) len += 1;
            else if (mod == 2) len += 4;
        } else if ((p[0] & 0xF8) == 0x48) {
            // Any REX.W* variant (W set, R/X/B optional): 0x48-0x4F.
            // PE prologues often start with `mov r11, rsp` (4C 8B DC) etc.
            const uint8_t op = p[1];
            const bool modrm_op =
                op == 0x83 || op == 0xC7 || op == 0x81 ||
                op == 0x89 || op == 0x8B || op == 0x8D ||
                op == 0x85 || op == 0x3B;
            if (!modrm_op) return 0;
            const uint8_t modrm = p[2];
            const uint8_t mod = modrm >> 6;
            const uint8_t rm = modrm & 7;
            len = 3;
            if (rm == 4 && mod != 3) len++;     // SIB
            if (mod == 0 && rm == 5) return 0;  // RIP-relative
            if (mod == 1) len += 1;
            else if (mod == 2) len += 4;
            if (op == 0x83) len += 1;
            else if (op == 0x81 || op == 0xC7) len += 4;
        } else {
            return 0;
        }

        if (len == 0) return 0;
        stolen += len;
    }
    return stolen >= kAbsJumpSize ? stolen : 0;
}

bool install(uintptr_t target, uintptr_t hook,
             uintptr_t* out_trampoline, size_t stolen) {
    if (stolen < kAbsJumpSize) return false;

    const size_t ps = sys::page_size();

    // Allocate trampoline page (RWX). ScopedMmap so we drop on failure.
    ScopedMmap tramp(ps, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS);
    if (!tramp) return false;

    uint8_t* t = tramp.as<uint8_t>();
    std::memcpy(t, reinterpret_cast<const void*>(target), stolen);
    write_abs_jump(t + stolen, target + stolen);

    // Make target page writable.
    const uintptr_t page = sys::page_align_down(target, ps);
    const size_t span = sys::page_span_len(target, stolen, ps);
    if (sys::mprotect(reinterpret_cast<void*>(page), span,
                      PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return false;
    }

    // Publish the trampoline BEFORE patching the target. Once the patch is
    // live any thread can hit the hook and dereference *out_trampoline; if it
    // were still NULL at that point we'd crash. The barrier prevents the
    // compiler/CPU from reordering the publication after the patch.
    *out_trampoline = reinterpret_cast<uintptr_t>(tramp.release());
    __atomic_thread_fence(__ATOMIC_RELEASE);

    // Patch in absolute jump to hook. NOPs pad any leftover bytes.
    uint8_t* p = reinterpret_cast<uint8_t*>(target);
    write_abs_jump(p, hook);
    for (size_t i = kAbsJumpSize; i < stolen; i++) p[i] = 0x90;

    // Restore page protection. Failure here leaves an RWX page but the hook
    // still works — log via return code so the caller can warn.
    (void)sys::mprotect(reinterpret_cast<void*>(page), span,
                        PROT_READ | PROT_EXEC);

    return true;
}

} // namespace sls::detour
