#pragma once

#include "../sdk/PackageInfo.hpp"

#include <cstdint>
#include <vector>

namespace Package {
    // True once tryInitFakeLicenseOnce has injected into pkg0 successfully.
    bool isActive();

    // Append appId into vec's spare capacity only (no realloc). Returns false if
    // the vector is full (caller logs + drops; first version never reallocs — see
    // plan note: observed SPARE=10 covers typical lua sets).
    // Caller must hold the package mutex (no internal locking).
    bool appendAppIdInPlace(CUtlVector<uint32_t>* vec, uint32_t appId);

    // Linear find + overwrite-with-last + m_Size--. Returns false if absent.
    // Caller must hold the package mutex (no internal locking).
    bool findAndFastRemove(CUtlVector<uint32_t>* vec, uint32_t appId);

    // Capture seam (set by hooks.cpp). pkg0 PackageInfo*, CUser*.
    void setInjectedPackage(void* pkg);
    void setCUser(void* cuser);

    // Read accessor for the cached CUser*. Captured from CUser hooks and, if
    // needed, lazily resolved from CSteamEngine::getUser(0). Used by
    // LibraryInject to reach the per-user CConfigStore at a pattern-resolved
    // offset inside CUser.
    void* getCUser();

    // onDepotsChanged callback target (lua FileWatcher thread). Only flags a
    // pending change; the real pkg0 mutation runs on a Steam thread.
    void notifyLicenseChanged();

    // Queue already-reconciled config appId changes for live pkg0 mutation. Safe
    // from the config FileWatcher thread; drained by pumpOnSteamThread.
    void queueAppIdChanges(const std::vector<uint32_t>& additions, const std::vector<uint32_t>& removals);

    // One-shot: inject the reconciled AdditionalApps set into pkg0 + Mark/Process.
    // Safe to call repeatedly; only runs once when pkg0+CUser captured and
    // Status==Available.
    void tryInitFakeLicenseOnce(const char* source);

    // Called from a Steam thread (hkUser_CheckAppOwnership). Runs the one-shot
    // initial injection, then drains pending lua/yaml hot-reload changes — keeping
    // ALL Steam-table mutation on the Steam thread (doing it on the foreign
    // FileWatcher thread crashes Steam).
    void pumpOnSteamThread(const char* source);
}
