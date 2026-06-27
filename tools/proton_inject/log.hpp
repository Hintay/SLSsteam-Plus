// Append-only debug log to ~/.sls_inject.log. Safe in clone() threads.
#pragma once

namespace sls::log {

void dbg(const char* msg);

} // namespace sls::log
