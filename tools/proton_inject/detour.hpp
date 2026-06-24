// In-process detour installer: replaces the first ~14 bytes of `target` with
// `movabs rax, hook; jmp rax`, and copies the stolen prologue to a trampoline
// suffixed with the same jmp pattern back to (target + stolen).
//
// Caller must pass `hook` that respects target's calling convention.
#pragma once

#include <cstddef>
#include <cstdint>

namespace sls::detour {

// Decode the function prologue at `target` and report the number of bytes that
// must be stolen for a 14-byte absolute jump. Returns 0 if undecodable.
size_t prologue_steal_bytes(const uint8_t* target);

// Install the detour. On success writes the trampoline address into
// `*out_trampoline` and returns true. On failure leaves target unmodified.
bool install(uintptr_t target, uintptr_t hook,
             uintptr_t* out_trampoline, size_t stolen);

} // namespace sls::detour
