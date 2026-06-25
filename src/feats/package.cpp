#include "package.hpp"
#include "steamui.hpp"

#include "../hooks.hpp"
#include "../config.hpp"
#include "apps.hpp"
#include "../lua/LuaLoader.hpp"
#include "../ownership.hpp"
#include "../log.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <vector>

namespace {
    std::atomic<bool>  g_active{false};
    std::atomic<void*> g_pkg{nullptr};
    std::atomic<void*> g_cuser{nullptr};
    std::atomic<bool>  g_pumpActive{false};
    std::mutex         g_injectMtx;   // guards pkg0 mutation and cross-thread pending-change queues
    // Set by notifyLicenseChanged (lua FileWatcher thread); drained by
    // pumpOnSteamThread (Steam thread) so the actual pkg0 mutation + Mark/Process
    // never runs on the foreign FileWatcher thread (cross-thread race → crash).
    std::atomic<bool>  g_pendingChange{false};
    std::vector<uint32_t> g_pendingConfigAdditions;
    std::vector<uint32_t> g_pendingConfigRemovals;

    // Grow AppIdVec in batches to amortise realloc calls. 16 exceeds the typical lua
    // set size (~10 ids) so a single grow is almost always enough.
    static constexpr int kAppIdVecGrowBatch = 16;
    using SteadyClock = std::chrono::steady_clock;

    static int64_t elapsedMs(SteadyClock::time_point start)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(SteadyClock::now() - start).count();
    }

    struct ThreadPumpGuard {
        bool& active;
        bool entered;

        explicit ThreadPumpGuard(bool& active) : active(active), entered(!active)
        {
            if (entered) active = true;
        }

        ~ThreadPumpGuard()
        {
            if (entered) active = false;
        }
    };

    struct GlobalPumpGuard {
        bool entered;

        GlobalPumpGuard() : entered(false)
        {
            bool expected = false;
            entered = g_pumpActive.compare_exchange_strong
            (
                expected,
                true,
                std::memory_order_acq_rel,
                std::memory_order_acquire
            );
        }

        ~GlobalPumpGuard()
        {
            if (entered)
            {
                g_pumpActive.store(false, std::memory_order_release);
            }
        }
    };

    static void appendUnique(std::vector<uint32_t>& dst, const std::vector<uint32_t>& src)
    {
        for (uint32_t id : src) {
            bool found = false;
            for (uint32_t existing : dst) {
                if (existing == id) {
                    found = true;
                    break;
                }
            }
            if (!found) dst.push_back(id);
        }
    }
}

namespace Package {

bool isActive() { return g_active.load(std::memory_order_acquire); }

bool appendAppIdInPlace(CUtlVector<uint32_t>* vec, uint32_t appId)
{
    if (!vec || vec->m_Size < 0 || !vec->m_Memory.m_pMemory) return false;
    if (static_cast<uint32_t>(vec->m_Size) >= vec->m_Memory.m_nAllocationCount)
        return false; // no spare capacity; first version never reallocs
    vec->m_Memory.m_pMemory[vec->m_Size] = appId;
    vec->m_Size += 1;
    return true;
}

bool findAndFastRemove(CUtlVector<uint32_t>* vec, uint32_t appId)
{
    if (!vec || !vec->m_Memory.m_pMemory) return false;
    for (int32_t i = 0; i < vec->m_Size; ++i) {
        if (vec->m_Memory.m_pMemory[i] == appId) {
            vec->m_Memory.m_pMemory[i] = vec->m_Memory.m_pMemory[vec->m_Size - 1];
            vec->m_Size -= 1;
            return true;
        }
    }
    return false;
}

// Presence check (no mutation). Used on the live hot-reload path to leave already-injected
// apps untouched instead of remove+re-append: churning an app's pkg0 membership makes the
// following markAndProcess re-evaluate its cloud state, which paints the transient "Steam
// Cloud out of date" badge on apps the user has played. Already present == no change.
static bool containsAppId(CUtlVector<uint32_t>* vec, uint32_t appId)
{
    if (!vec || !vec->m_Memory.m_pMemory) return false;
    for (int32_t i = 0; i < vec->m_Size; ++i)
        if (vec->m_Memory.m_pMemory[i] == appId) return true;
    return false;
}

// Append into spare capacity; if full, grow via Steam's CUtlMemory::Grow then retry.
// Caller holds g_injectMtx. Returns false only if grow is unavailable or still fails.
static bool appendAppIdGrowing(CUtlVector<uint32_t>* vec, uint32_t appId)
{
    if (!vec) return false;
    if (appendAppIdInPlace(vec, appId)) return true;   // spare slot existed
    if (!Hooks::oCUtlMemoryGrow) return false;
    // NOTE: Grow triggers a realloc that frees the old m_pMemory; Steam threads
    // reading AppIdVec lock-free during this window risk a use-after-free — an
    // escalation over the in-place-write race (which only risks a stale value).
    // Accepted per architecture; grow only fires when the lua set exceeds the
    // initial spare (~10). Monitor the grow path during Deck validation.
    Hooks::oCUtlMemoryGrow(&vec->m_Memory, kAppIdVecGrowBatch); // grow by a batch (amortize)
    return appendAppIdInPlace(vec, appId);              // retry after grow
}

void setInjectedPackage(void* pkg) { g_pkg.store(pkg, std::memory_order_release); }
void setCUser(void* cuser)         { g_cuser.store(cuser, std::memory_order_release); }
void* getCUser()                   { return g_cuser.load(std::memory_order_acquire); }

void queueAppIdChanges(const std::vector<uint32_t>& additions, const std::vector<uint32_t>& removals)
{
    if (!g_config.packageInjection.get()) return;
    if (additions.empty() && removals.empty()) return;

    {
        std::lock_guard<std::mutex> lock(g_injectMtx);
        appendUnique(g_pendingConfigAdditions, additions);
        appendUnique(g_pendingConfigRemovals, removals);
    }
    g_pendingChange.store(true, std::memory_order_release);
}

// Mark package 0 changed + process pending license updates so Steam re-evaluates
// ownership without a restart. Do not call while holding g_injectMtx: Steam may
// re-enter our hooks during ProcessPendingLicenseUpdates, and re-taking the mutex
// would deadlock. Returns false if deps are not ready.
static bool markAndProcess(const char* source)
{
    void* cuser = g_cuser.load(std::memory_order_acquire);
    if (!cuser || !Hooks::oMarkLicenseAsChanged || !Hooks::oProcessPendingLicenseUpdates)
    {
        g_pLog->warn("Package: markAndProcess missing deps cuser=%p mark=%p process=%p\n",
            cuser,
            reinterpret_cast<void*>(Hooks::oMarkLicenseAsChanged),
            reinterpret_cast<void*>(Hooks::oProcessPendingLicenseUpdates));
        return false;
    }
    // Mark/Process mutate the CUser license table that Steam's own threads walk.
    // Doing this from the foreign FileWatcher thread
    // corrupted Steam and crashed the IPC thread (SIGSEGV). Both injection paths now
    // run on a Steam thread via pumpOnSteamThread. The PackageInjection config gate
    // remains the kill switch.
    const auto start = SteadyClock::now();
    Hooks::oMarkLicenseAsChanged(cuser, 0 /*pkgId*/, 1 /*bChanged*/);
    const int64_t markMs = elapsedMs(start);
    // ProcessPendingLicenseUpdates' own return value is logged for diagnosis only.
    // It must NOT gate downstream UI/diag work: once the license is Marked and the
    // update pump has run with deps ready, the change is considered applied. The
    // return contract here is "did we run Mark/Process" (deps were ready), matching
    // the "deps not ready" warnings at the call sites.
    const auto processStart = SteadyClock::now();
    const bool processResult = Hooks::oProcessPendingLicenseUpdates(cuser);
    const int64_t processMs = elapsedMs(processStart);
    g_pLog->debug
    (
        "Package: ProcessPendingLicenseUpdates(source=%s, mark_ms=%lli, process_ms=%lli, total_ms=%lli) -> %i\n",
        source ? source : "unknown",
        static_cast<long long>(markMs),
        static_cast<long long>(processMs),
        static_cast<long long>(elapsedMs(start)),
        processResult
    );
    return true;
}

void tryInitFakeLicenseOnce(const char* source)
{
    if (!g_config.packageInjection.get()) return;
    if (g_active.load(std::memory_order_acquire)) return;
    void* pkg = g_pkg.load(std::memory_order_acquire);
    if (!pkg || !g_cuser.load(std::memory_order_acquire)) return;
    if (PackageInfo::status(pkg) != 0) return; // not Available

    const auto start = SteadyClock::now();
    size_t added = 0, dropped = 0;
    {
        const auto mutationStart = SteadyClock::now();
        std::lock_guard<std::mutex> lock(g_injectMtx);
        if (g_active.load(std::memory_order_acquire)) return; // double-checked

        auto* vec = PackageInfo::appIdVec(pkg);
        const auto ids = Ownership::getControlledAppIds();
        for (uint32_t id : ids) {
            findAndFastRemove(vec, id);                  // drop any existing copy (de-dup)
            if (appendAppIdGrowing(vec, id)) ++added; else ++dropped;
        }
        g_active.store(true, std::memory_order_release);
        g_pLog->debug("Package: init mutation(source=%s, added=%zu, dropped=%zu, elapsed_ms=%lli)\n", source ? source : "unknown", added, dropped, static_cast<long long>(elapsedMs(mutationStart)));
    }

    if (dropped) g_pLog->warn("Package: %zu ids dropped — pkg0 AppIdVec out of spare capacity\n", dropped);
    if (!markAndProcess(source))
        g_pLog->warn("Package: markAndProcess skipped at init via %s (deps not ready)\n", source ? source : "unknown");
    g_pLog->once("Package: injected %zu appIds into pkg0 via %s, license re-evaluated\n", added, source ? source : "unknown");
    g_pLog->debug("Package: init timing(source=%s, total_ms=%lli)\n", source ? source : "unknown", static_cast<long long>(elapsedMs(start)));
}

// Apply queued config/lua hot-reload add/removes to pkg0 + live re-evaluate. MUST
// run on a Steam thread: doing this from the foreign FileWatcher thread races
// Steam's license/IPC threads and corrupts them (observed SIGSEGV). Only
// reached via pumpOnSteamThread after g_active, so pkg0 is captured and injected.
static void applyPendingChanges(const char* source)
{
    void* pkg = g_pkg.load(std::memory_order_acquire);
    if (!pkg) return;

    const auto start = SteadyClock::now();
    size_t changed = 0;
    std::vector<uint32_t> removals;
    std::vector<uint32_t> additions;
    std::vector<uint32_t> removed;
    int64_t mutationMs = 0;
    {
        const auto mutationStart = SteadyClock::now();
        std::lock_guard<std::mutex> lock(g_injectMtx);
        auto* vec = PackageInfo::appIdVec(pkg);
        appendUnique(removals, LuaLoader::takePendingRemovals());
        appendUnique(removals, g_pendingConfigRemovals);
        appendUnique(additions, LuaLoader::takePendingAdditions());
        appendUnique(additions, g_pendingConfigAdditions);
        g_pendingConfigRemovals.clear();
        g_pendingConfigAdditions.clear();

        // Snapshot the controlled set once: MTVariable::get copies the whole set on
        // every call, so a per-id isControlledApp() would copy it 2*N times here.
        const auto controlled = Ownership::getControlledAppIdSet();

        for (uint32_t id : removals) {
            if (controlled.contains(id)) continue;
            if (findAndFastRemove(vec, id)) { ++changed; removed.push_back(id); }
        }
        for (uint32_t id : additions) {
            if (!controlled.contains(id)) continue;
            // Already injected? Leave it. A hot-reload re-queues the whole lua set (mostly
            // already-present apps); remove+re-appending them churns their license membership
            // so markAndProcess re-evaluates their cloud state and paints the transient
            // "Steam Cloud out of date" badge on played apps. Only genuinely-new apps are a
            // real change and need marking. (Skipping also keeps the vec de-duped.)
            if (containsAppId(vec, id)) continue;
            if (appendAppIdGrowing(vec, id)) ++changed;
        }
        mutationMs = elapsedMs(mutationStart);
    }

    // `removed` only ever holds non-controlled ids (controlled ones are skipped above),
    // so no isControlledApp re-check is needed here.
    for (uint32_t id : removed)
        Ownership::unmarkGenuinelyOwned(id);

    bool processed = false;
    if (changed) {
        processed = markAndProcess(source);
        if (!processed) g_pLog->warn("Package: markAndProcess skipped on live change via %s (deps not ready)\n", source ? source : "unknown");
        g_pLog->info
        (
            "Package: live license change applied via %s (%zu genuinely new/removed)\n",
            source ? source : "unknown",
            changed
        );
        g_pLog->debug
        (
            "Package: live change timing(source=%s, mutation_ms=%lli, total_ms=%lli)\n",
            source ? source : "unknown",
            static_cast<long long>(mutationMs),
            static_cast<long long>(elapsedMs(start))
        );
    }
    if (processed)
        for (uint32_t id : removed) SteamUI::removeAppAndSendChange(id);
}

// onDepotsChanged callback — runs on the lua FileWatcher thread. Do NOT touch pkg0
// / Mark/Process here (cross-thread race → crash). Just signal; pumpOnSteamThread
// drains it on a Steam thread.
void notifyLicenseChanged()
{
    if (!g_config.packageInjection.get()) return;
    g_pendingChange.store(true, std::memory_order_release);
}

// Runs on a Steam thread. Performs the one-shot initial injection, then drains
// pending lua/yaml hot-reload changes — all Steam-thread-side so nothing mutates
// Steam's tables from a foreign thread. The thread-local guard blocks re-entry from
// ProcessPendingLicenseUpdates callbacks; the global guard serializes multiple Steam
// threads so pkg0 mutation and Mark/Process never overlap.
void pumpOnSteamThread(const char* source)
{
    if (!g_config.packageInjection.get()) return;   // feature off: nothing to pump

    static thread_local bool s_inPump = false;
    ThreadPumpGuard guard(s_inPump);
    if (!guard.entered) return;

    // Steady-state fast path: once injected with nothing queued, skip the two atomic
    // RMWs below (global CAS + drain exchange) on this hot path. The pending flag is
    // sticky, so anything set after this load is drained by the next pump.
    if (g_active.load(std::memory_order_acquire)
        && !g_pendingChange.load(std::memory_order_acquire))
        return;

    GlobalPumpGuard globalGuard;
    if (!globalGuard.entered) return;

    tryInitFakeLicenseOnce(source);
    if (!g_active.load(std::memory_order_acquire)) return;   // not injected yet; pending stays set

    while (g_pendingChange.exchange(false, std::memory_order_acq_rel))
    {
        applyPendingChanges(source);
    }
}

} // namespace Package
