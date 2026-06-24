// /proc/self/maps scanner — module base + file-path lookup by needle.
#pragma once

#include <cstddef>
#include <cstdint>

namespace sls::maps {

inline constexpr size_t kMapsBufSize = 256 * 1024;

// Look up the first read-only mapping (typically the PE/ELF header) whose
// path contains `needle` and return its base address. The full mapping file
// path is written to `out_path` (optional). Returns 0 / empty path on miss.
uintptr_t find_module_base_and_path(const char* needle,
                                    char* out_path, size_t out_path_size);

} // namespace sls::maps
