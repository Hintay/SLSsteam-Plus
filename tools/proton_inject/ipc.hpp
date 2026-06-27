// IPC client: connects to SLSsteam's abstract Unix socket using the launch
// token from the environment, receives the DLL path, returns it as a Wine NT
// path (UTF-16LE, "\??\unix/...") suitable for LdrLoadDll.
#pragma once

#include <cstddef>
#include <cstdint>

namespace sls::ipc {

// Writes the resolved UTF-16LE NT path into `out` (capacity `out_chars` u16
// code units, including terminator). Returns true on success.
bool resolve_dll_path(uint16_t* out, size_t out_chars);

} // namespace sls::ipc
