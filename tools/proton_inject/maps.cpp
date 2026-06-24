#include "maps.hpp"

#include "raii.hpp"
#include "syscalls.hpp"

#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>

namespace sls::maps {

namespace {

uintptr_t hex_to_ulong(const char* s) {
    uintptr_t v = 0;
    for (; *s; s++) {
        const char c = *s;
        if (c >= '0' && c <= '9') v = v * 16 + static_cast<uintptr_t>(c - '0');
        else if (c >= 'a' && c <= 'f') v = v * 16 + static_cast<uintptr_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v = v * 16 + static_cast<uintptr_t>(c - 'A' + 10);
        else break;
    }
    return v;
}

// Read /proc/self/maps into the buffer. Returns total bytes read (<= bufsz-1)
// and null-terminates. Returns 0 on failure.
ssize_t read_maps(char* buf, size_t bufsz) {
    ScopedFd fd(sys::open("/proc/self/maps", O_RDONLY));
    if (!fd.valid()) return 0;
    ssize_t total = 0;
    while (total < static_cast<ssize_t>(bufsz) - 1) {
        const ssize_t r = sys::read(fd.get(), buf + total,
                                    bufsz - 1 - static_cast<size_t>(total));
        if (r <= 0) break;
        total += r;
    }
    if (total <= 0) return 0;
    buf[total] = '\0';
    return total;
}

// Extract file path field (6th field) from a single /proc/self/maps line.
// Returns nullptr if absent. `line` may not be null-terminated mid-line; the
// caller already replaces '\n' with '\0' on the consumed line.
const char* path_field(const char* line) {
    const char* p = line;
    int fields = 0;
    while (*p && fields < 5) {
        while (*p == ' ') p++;
        while (*p && *p != ' ') p++;
        fields++;
    }
    while (*p == ' ') p++;
    return *p == '/' ? p : nullptr;
}

} // namespace

uintptr_t find_module_base_and_path(const char* needle,
                                    char* out_path, size_t out_path_size) {
    if (out_path && out_path_size > 0) out_path[0] = '\0';

    auto buf = scratch_mmap(kMapsBufSize);
    if (!buf) return 0;
    const ssize_t n = read_maps(buf.as<char>(), kMapsBufSize);
    if (n <= 0) return 0;

    uintptr_t result = 0;
    char* line = buf.as<char>();
    while (*line) {
        char* eol = std::strchr(line, '\n');
        if (eol) *eol = '\0';

        // Match the first readable mapping that contains the needle in its path;
        // the read-only mapping is typically the file header (lowest base).
        if (std::strstr(line, needle) && std::strstr(line, " r--p ")) {
            result = hex_to_ulong(line);
            if (out_path && out_path_size > 0) {
                const char* p = path_field(line);
                if (p) {
                    size_t cp = std::strlen(p);
                    if (cp >= out_path_size) cp = out_path_size - 1;
                    std::memcpy(out_path, p, cp);
                    out_path[cp] = '\0';
                    // strip trailing newlines / CR (defensive)
                    while (cp > 0 && (out_path[cp - 1] == '\n' || out_path[cp - 1] == '\r')) {
                        out_path[--cp] = '\0';
                    }
                }
            }
            break;
        }
        if (!eol) break;
        line = eol + 1;
    }
    return result;
}

} // namespace sls::maps
