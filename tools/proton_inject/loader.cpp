#include "loader.hpp"

#include "detour.hpp"
#include "ipc.hpp"
#include "log.hpp"
#include "maps.hpp"
#include "nt_api.hpp"
#include "pe.hpp"

#include <atomic>
#include <cstdint>
#include <cstring>

namespace sls::loader {

namespace {

using namespace sls::nt;

// ── State (process-wide singleton) ──────────────────────────────────

uintptr_t       g_LdrLoadDll_trampoline = 0;
// Single CAS for the whole "we have loaded (or are loading) the helper"
// transition. Whichever path (trigger DLL seen / scan-says-pending) wins
// the CAS does the IPC + LdrLoadDll exactly once per process.
std::atomic<bool> g_helper_loading{false};
// Set by scan path when the trigger DLL is already mapped at install time.
// The next LdrLoadDll fire from a real PE thread picks this up.
std::atomic<bool> g_pending{false};

constexpr int kMaxNameChars = 256;

// ── Trigger name matching ───────────────────────────────────────────
//
// We want to fire as soon as the host process establishes its Steam IPC
// pipe. That happens inside SteamAPI_Init, which lives in steam_api64.dll
// (and lazy-loads steamclient.dll on first use). Either signals that the
// host is the game process, not a Wine system process.

bool u16_iequals_suffix(const uint16_t* s, int nchars, const char* needle) {
    const int nlen = static_cast<int>(std::strlen(needle));
    if (nchars < nlen) return false;
    const int start = nchars - nlen;
    for (int i = 0; i < nlen; i++) {
        uint16_t a = s[start + i];
        char b = needle[i];
        if (a >= 'A' && a <= 'Z') a = static_cast<uint16_t>(a + 32);
        if (b >= 'A' && b <= 'Z') b = static_cast<char>(b + 32);
        if (a != static_cast<uint16_t>(static_cast<unsigned char>(b))) return false;
    }
    return true;
}

bool name_is_trigger(const UNICODE_STRING* name) {
    if (!name || !name->Buffer || name->Length == 0) return false;
    int chars = name->Length / 2;
    if (chars > kMaxNameChars) chars = kMaxNameChars;
    return u16_iequals_suffix(name->Buffer, chars, "steam_api64.dll")
        || u16_iequals_suffix(name->Buffer, chars, "steamclient.dll");
}

// Resolve helper DLL path via IPC and LdrLoadDll it. CAS-guarded so we run
// exactly once per process even if multiple trigger sources fire (hook +
// pending). Caller must be on a Wine PE thread (LoaderLock-safe) — i.e.
// either inside hook_LdrLoadDll or invoked from the original LdrLoadDll
// callee's stack.
void load_helper_now() {
    bool expected = false;
    if (!g_helper_loading.compare_exchange_strong(expected, true,
                                                   std::memory_order_acq_rel)) {
        return; // already done / in flight
    }

    uint16_t dll_path[4096];
    if (!ipc::resolve_dll_path(dll_path, sizeof(dll_path) / sizeof(dll_path[0]))) {
        log::dbg("resolve failed");
        // Re-arm so a later trigger (e.g. token finally appears) can retry.
        // In practice we won't get a second chance, but it's harmless.
        g_helper_loading.store(false, std::memory_order_release);
        return;
    }

    size_t chars = 0;
    while (dll_path[chars]) chars++;

    UNICODE_STRING us{};
    us.Length        = static_cast<uint16_t>(chars * 2);
    us.MaximumLength = static_cast<uint16_t>((chars + 1) * 2);
    us.Buffer        = dll_path;

    auto orig = reinterpret_cast<LdrLoadDll_fn>(g_LdrLoadDll_trampoline);
    void* hModule = nullptr;
    const NTSTATUS load_st = orig(nullptr, 0, &us, &hModule);
    log::dbg(load_st == kStatusSuccess ? "helper loaded" : "helper load FAILED");
}

// ── The detour ──────────────────────────────────────────────────────
//
// Runs on the host thread that called LdrLoadDll — guaranteed to be a real
// Wine PE thread with an NT TEB set up. Safe to make further PE calls.
//
// LoaderLock note: we're invoked from inside LdrLoadDll, so LoaderLock is
// held by this thread. Re-entering LdrLoadDll for our own DLL on the same
// thread re-acquires the (recursive) critical section, which is legal. The
// risk is the injected payload's DllMain — but standard Detours-style
// payloads only install hooks in DllMain and return promptly, so this
// matches every other inline-injection pipeline.

static __attribute__((ms_abi))
NTSTATUS hook_LdrLoadDll(
    PWSTR SearchPath, ULONG Flags,
    UNICODE_STRING* DllName, void** BaseAddress) {

    auto orig = reinterpret_cast<LdrLoadDll_fn>(g_LdrLoadDll_trampoline);
    const NTSTATUS st = orig(SearchPath, Flags, DllName, BaseAddress);

    if (st != kStatusSuccess) return st;

    const bool trigger_seen   = name_is_trigger(DllName);
    const bool pending_pickup = g_pending.exchange(false, std::memory_order_acq_rel);

    if (trigger_seen || pending_pickup) {
        if (trigger_seen)   log::dbg("trigger seen, loading helper");
        if (pending_pickup) log::dbg("pending pickup, loading helper");
        load_helper_now();
    }
    return st;
}

} // namespace

bool install_trigger() {
    if (g_LdrLoadDll_trampoline) return true; // already installed

    char pe_path[512] = {};
    const uintptr_t pe_base = maps::find_module_base_and_path(
        "x86_64-windows/ntdll.dll", pe_path, sizeof(pe_path));
    if (!pe_base || !pe_path[0]) return false; // PE ntdll not mapped yet

    const uint32_t rva = pe::find_export_rva(pe_path, "LdrLoadDll");
    if (!rva) {
        log::dbg("no LdrLoadDll RVA");
        return false;
    }

    const uintptr_t target = pe_base + rva;
    const size_t stolen = detour::prologue_steal_bytes(
        reinterpret_cast<const uint8_t*>(target));
    if (stolen == 0) {
        log::dbg("prologue too short");
        return false;
    }

    if (!detour::install(target,
                          reinterpret_cast<uintptr_t>(&hook_LdrLoadDll),
                          &g_LdrLoadDll_trampoline, stolen)) {
        log::dbg("detour install failed");
        return false;
    }
    log::dbg("LdrLoadDll detour live");
    return true;
}

bool trigger_already_loaded() {
    // The detour-installer scan above uses "x86_64-windows/ntdll.dll" to
    // find Wine's PE ntdll. Wine maps every PE DLL under that same path
    // prefix, so the trigger DLL — if loaded — sits next to it. We pass
    // a dummy path buffer because we only care about the base != 0.
    char dummy[8];
    return maps::find_module_base_and_path("steam_api64.dll", dummy, sizeof(dummy)) != 0
        || maps::find_module_base_and_path("steamclient.dll", dummy, sizeof(dummy)) != 0;
}

void mark_pending() {
    g_pending.store(true, std::memory_order_release);
}

} // namespace sls::loader
