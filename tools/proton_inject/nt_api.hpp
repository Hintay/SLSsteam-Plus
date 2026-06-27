// Minimal NT typedefs needed to call PE ntdll's LdrLoadDll from our
// LD_PRELOAD'd .so. We do NOT touch unix/ntdll.so functions anymore —
// the new model loads the helper DLL by calling LdrLoadDll directly in
// the process whose address space we share.
#pragma once

#include <cstddef>
#include <cstdint>

namespace sls::nt {

using NTSTATUS = int32_t;
using ULONG = uint32_t;
using PWSTR = uint16_t*;

struct UNICODE_STRING {
    uint16_t Length;          // bytes (not chars), excluding NUL
    uint16_t MaximumLength;   // bytes (not chars), including NUL
    uint32_t _pad;            // x86_64 padding to align Buffer
    PWSTR    Buffer;
};

// PE ntdll's LdrLoadDll uses Microsoft x64 calling convention (RCX/RDX/R8/R9
// + 0x20 shadow space). gcc's __attribute__((ms_abi)) emits matching code
// from our Linux ELF caller. Signature mirrors Wine's:
//   NTSTATUS LdrLoadDll(LPCWSTR path, DWORD flags, const UNICODE_STRING*, HMODULE*)
using LdrLoadDll_fn = NTSTATUS __attribute__((ms_abi)) (*)(
    PWSTR SearchPath,
    ULONG Flags,
    UNICODE_STRING* DllName,
    void** BaseAddress);

inline constexpr NTSTATUS kStatusSuccess = 0;

} // namespace sls::nt
