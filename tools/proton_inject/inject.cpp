// sls_proton_inject.so — LD_PRELOAD helper for Proton DLL injection.
//
// Flow:
//   1. ctor: install LdrLoadDll detour if PE ntdll is already mapped, else
//      spawn a clone() poll thread that retries until PE ntdll appears.
//   2. once the detour is live, scan /proc/self/maps for an already-loaded
//      trigger DLL (steam_api64.dll / steamclient.dll). If found, mark a
//      "pending pickup" flag — the next LdrLoadDll call (which Wine PE
//      processes make plenty of) will pick it up from inside the hook on a
//      real PE thread.
//   3. detour fires from a Wine PE thread on either path; it then resolves
//      the helper DLL path via SLSsteam IPC and LdrLoadDlls it into THIS
//      process — which is the game process, since it touched steam_api.
//
// IPC happens INSIDE the detour, not in this ctor. That keeps every non-game
// Wine PE process (wineboot, services.exe, winedevice.exe, …) off the
// SLSsteam control socket entirely — they never load steam_api64.dll, never
// fire the trigger, never IPC. Talking to the server only on actual game
// processes means a Wine helper that started under a stale env (e.g. forked
// off an outdated wineserver) never sends a bogus token at all.

#include "loader.hpp"
#include "log.hpp"
#include "syscalls.hpp"

#include <cstddef>
#include <cstdint>
#include <sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace sls::init {

namespace {

constexpr size_t kPollStackSize = 2 * 1024 * 1024;
constexpr int    kPollIntervalMs = 50;
constexpr int    kPollMaxIterations = 600; // 30 s ceiling

// Install detour + arm scan-pending. Common path shared by the immediate
// (ctor) install and the poll-thread install — same scan happens after
// each successful install so the trigger-already-loaded race is handled
// no matter which path actually placed the hook.
void post_install_scan() {
    if (loader::trigger_already_loaded()) {
        loader::mark_pending();
        log::dbg("trigger already loaded — pending pickup armed");
    }
}

int poll_fn(void* /*arg*/) {
    bool installed = false;
    for (int i = 0; i < kPollMaxIterations; i++) {
        if (loader::install_trigger()) {
            log::dbg("ACTIVE (poll)");
            installed = true;
            post_install_scan();
            break;
        }
        sys::sleep_ms(kPollIntervalMs);
    }
    if (!installed) log::dbg("poll: gave up");
    ::syscall(SYS_exit, 0);
    return 0;
}

void spawn_poll_thread() {
    void* stack = sys::mmap(nullptr, kPollStackSize, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) return;
    ::clone(poll_fn, static_cast<char*>(stack) + kPollStackSize,
            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD,
            nullptr);
}

} // namespace

void init() {
    log::dbg("ctor");
    if (loader::install_trigger()) {
        log::dbg("ACTIVE (immediate)");
        post_install_scan();
        return;
    }

    // PE ntdll not mapped yet (e.g. we're still in wine64-preloader's early
    // init). Spawn a poll thread that retries quietly.
    spawn_poll_thread();
}

} // namespace sls::init

extern "C" __attribute__((constructor))
void sls_proton_inject_init() {
    sls::init::init();
}
