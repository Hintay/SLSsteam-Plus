// PE export resolver — parses a Windows .dll on disk to find an export's RVA.
// The caller adds the runtime base address to get an absolute pointer.
#pragma once

#include <cstdint>

namespace sls::pe {

// Returns 0 on failure, the RVA on success. Forwarded exports return 0.
uint32_t find_export_rva(const char* path, const char* func_name);

} // namespace sls::pe
