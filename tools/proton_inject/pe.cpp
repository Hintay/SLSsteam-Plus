#include "pe.hpp"

#include "raii.hpp"
#include "syscalls.hpp"

#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>

namespace sls::pe {

namespace {

constexpr size_t kSectionHeaderSize = 40;

// Convert RVA to file offset using the section table. Returns (uint32_t)-1 on miss.
uint32_t rva_to_offset(const uint8_t* sec, int nsec, uint32_t rva) {
    for (int i = 0; i < nsec; i++) {
        const uint8_t* s = sec + static_cast<size_t>(i) * kSectionHeaderSize;
        const uint32_t vaddr = *reinterpret_cast<const uint32_t*>(s + 12);
        const uint32_t vsize = *reinterpret_cast<const uint32_t*>(s + 8);
        const uint32_t raw = *reinterpret_cast<const uint32_t*>(s + 20);
        if (rva >= vaddr && rva < vaddr + vsize) {
            return raw + (rva - vaddr);
        }
    }
    return static_cast<uint32_t>(-1);
}

} // namespace

uint32_t find_export_rva(const char* path, const char* func_name) {
    if (!path || !path[0] || !func_name) return 0;
    ScopedFd fd(sys::open(path, O_RDONLY));
    if (!fd.valid()) return 0;

    uint8_t dos[64];
    if (sys::read(fd.get(), dos, sizeof(dos)) != static_cast<ssize_t>(sizeof(dos))) return 0;
    if (dos[0] != 'M' || dos[1] != 'Z') return 0;

    const uint32_t pe_off = *reinterpret_cast<const uint32_t*>(dos + 0x3C);
    sys::lseek(fd.get(), pe_off, SEEK_SET);

    uint8_t pe_hdr[0x200];
    const ssize_t hdr_rd = sys::read(fd.get(), pe_hdr, sizeof(pe_hdr));
    if (hdr_rd < 0x88 + 8) return 0;
    if (pe_hdr[0] != 'P' || pe_hdr[1] != 'E') return 0;

    const uint16_t nsections = *reinterpret_cast<const uint16_t*>(pe_hdr + 6);
    const uint16_t opt_hdr_size = *reinterpret_cast<const uint16_t*>(pe_hdr + 20);
    const uint16_t magic = *reinterpret_cast<const uint16_t*>(pe_hdr + 24);

    uint32_t export_rva = 0, export_size = 0;
    if (magic == 0x20B) { // PE32+
        export_rva = *reinterpret_cast<const uint32_t*>(pe_hdr + 24 + 0x70);
        export_size = *reinterpret_cast<const uint32_t*>(pe_hdr + 24 + 0x74);
    } else if (magic == 0x10B) { // PE32
        export_rva = *reinterpret_cast<const uint32_t*>(pe_hdr + 24 + 0x60);
        export_size = *reinterpret_cast<const uint32_t*>(pe_hdr + 24 + 0x64);
    } else {
        return 0;
    }
    if (!export_rva || !export_size) return 0;

    const size_t sec_off = pe_off + 24 + opt_hdr_size;
    sys::lseek(fd.get(), sec_off, SEEK_SET);

    const size_t sec_sz = static_cast<size_t>(nsections) * kSectionHeaderSize;
    auto sec_buf = scratch_mmap(sec_sz);
    if (!sec_buf) return 0;
    if (sys::read(fd.get(), sec_buf.get(), sec_sz) != static_cast<ssize_t>(sec_sz)) return 0;
    const uint8_t* sec = sec_buf.as<uint8_t>();

    const uint32_t exp_foff = rva_to_offset(sec, nsections, export_rva);
    if (exp_foff == static_cast<uint32_t>(-1)) return 0;
    sys::lseek(fd.get(), exp_foff, SEEK_SET);

    uint8_t expdir[40];
    if (sys::read(fd.get(), expdir, sizeof(expdir)) != static_cast<ssize_t>(sizeof(expdir))) return 0;

    const uint32_t num_funcs = *reinterpret_cast<const uint32_t*>(expdir + 0x14);
    const uint32_t num_names = *reinterpret_cast<const uint32_t*>(expdir + 0x18);
    const uint32_t addr_rva = *reinterpret_cast<const uint32_t*>(expdir + 0x1C);
    const uint32_t name_rva = *reinterpret_cast<const uint32_t*>(expdir + 0x20);
    const uint32_t ord_rva = *reinterpret_cast<const uint32_t*>(expdir + 0x24);
    if (!num_funcs || !num_names) return 0;

    const size_t addr_sz = static_cast<size_t>(num_funcs) * 4;
    const size_t name_sz = static_cast<size_t>(num_names) * 4;
    const size_t ord_sz = static_cast<size_t>(num_names) * 2;

    auto tbl_buf = scratch_mmap(addr_sz + name_sz + ord_sz);
    if (!tbl_buf) return 0;

    uint32_t* addrs = tbl_buf.as<uint32_t>();
    uint32_t* names = reinterpret_cast<uint32_t*>(static_cast<char*>(tbl_buf.get()) + addr_sz);
    uint16_t* ords = reinterpret_cast<uint16_t*>(static_cast<char*>(tbl_buf.get()) + addr_sz + name_sz);

    uint32_t fo;
    fo = rva_to_offset(sec, nsections, addr_rva);
    if (fo != static_cast<uint32_t>(-1)) {
        sys::lseek(fd.get(), fo, SEEK_SET);
        sys::read(fd.get(), addrs, addr_sz);
    }
    fo = rva_to_offset(sec, nsections, name_rva);
    if (fo != static_cast<uint32_t>(-1)) {
        sys::lseek(fd.get(), fo, SEEK_SET);
        sys::read(fd.get(), names, name_sz);
    }
    fo = rva_to_offset(sec, nsections, ord_rva);
    if (fo != static_cast<uint32_t>(-1)) {
        sys::lseek(fd.get(), fo, SEEK_SET);
        sys::read(fd.get(), ords, ord_sz);
    }

    char name_buf[128];
    for (uint32_t i = 0; i < num_names; i++) {
        const uint32_t nfo = rva_to_offset(sec, nsections, names[i]);
        if (nfo == static_cast<uint32_t>(-1)) continue;
        sys::lseek(fd.get(), nfo, SEEK_SET);
        const ssize_t nr = sys::read(fd.get(), name_buf, sizeof(name_buf) - 1);
        if (nr <= 0) continue;
        name_buf[nr] = '\0';
        if (std::strcmp(name_buf, func_name) != 0) continue;
        if (ords[i] >= num_funcs) return 0;
        const uint32_t fn_rva = addrs[ords[i]];
        if (fn_rva >= export_rva && fn_rva < export_rva + export_size) {
            return 0; // forwarded export — unsupported
        }
        return fn_rva;
    }
    return 0;
}

} // namespace sls::pe
