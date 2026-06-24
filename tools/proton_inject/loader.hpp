// In-process DLL loader. Installs a detour on PE ntdll's LdrLoadDll so that
// the first time the host process loads Steam's client DLL (i.e. it just
// called SteamAPI_Init and now has IPC live), we LdrLoadDll our helper DLL
// into the SAME process — which is the game process by definition.
//
// IPC to SLSsteam (resolve_dll_path) is performed lazily INSIDE the detour
// when the trigger DLL is seen, not at constructor time. This keeps every
// non-game Wine PE process (wineboot, services.exe, winedevice.exe, …) off
// the control socket entirely — non-game processes simply never load
// steam_api64.dll, so they never trigger and never IPC. Only the process
// that will actually host the game ever talks to the server, so stale-token
// rejections from long-lived Wine helpers spawned with an outdated env
// cannot happen.
//
// This replaces the older cross-process injection model (NtCreateUserProcess
// hook + NtCreateThreadEx remote shellcode): we no longer target the child of
// a CreateProcessW call, we target the process that connected to Steam.
#pragma once

#include <cstdint>

namespace sls::loader {

// Install the LdrLoadDll detour. Returns true once the hook is live; returns
// false if PE ntdll isn't mapped yet (caller should poll/retry).
bool install_trigger();

// Scan /proc/self/maps for an already-loaded trigger DLL
// (steam_api64.dll / steamclient.dll). Used to catch the race where the
// trigger DLL was loaded between our SO mapping and our detour going live
// (poll path) — without this the detour would never fire for it.
bool trigger_already_loaded();

// Mark the helper-load as pending. The next LdrLoadDll call (from any
// thread, for any DLL) will pick this up inside the detour and load the
// helper, resolving the IPC path at that point. We defer to a real
// LdrLoadDll fire so the load happens on a Wine PE thread with a valid
// TEB — calling LdrLoadDll directly from our Linux clone() poll thread
// would crash on TEB-relative accesses.
void mark_pending();

} // namespace sls::loader
