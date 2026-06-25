#pragma once

#include <cstdint>
#include <unordered_set>

namespace ProtonInject
{
	// Called from IClientAppManager::LaunchApp hook. Reads the user's "Launch
	// Options" string via the per-user CConfigStore at a pattern-resolved CUser
	// offset (vtable slot 5) pre-fork so we can deterministically pick the
	// matching Flag entry.
	void onLaunchApp(uint32_t appId);

	// Called from Apps::sendGamesPlayed (outbound CMsgClientGamesPlayed
	// observer) every time Steam updates the CM with the live set of
	// currently-running game ids. Diffing against the last-seen set yields
	// "app stopped" events — the canonical Steam-side signal that fires on
	// every exit path (overlay "Exit Game", library "Stop", in-game exit),
	// independent of whether IClientAppManager::ShutdownApp fires and whether
	// the helper destructor inside the Wine PE tree gets a chance to run.
	// Pending-session tokens younger than a short race window are protected
	// to survive a quick exit-then-relaunch.
	void onGamesPlayedUpdate(const std::unordered_set<uint32_t>& runningAppIds);
}
