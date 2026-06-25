#pragma once

#include <cstdint>
#include <string>

// Shared helper for reading a user's Steam "Launch Options" string and
// substring-matching a launch-flag inside it. Used by LibraryInject (to pick
// the .dll/.so to inject before fork) and FakeAppIds (to flag-trigger runtime
// real→fake AppId mapping at LaunchApp time).
namespace LaunchOptions
{
	// Returns the contents of "Launch Options" for the given app, read from the
	// per-user CConfigStore via the pattern-resolved CUser+offset_ConfigStore.
	// Returns an empty string when the pattern is unavailable, CUser is not
	// captured, the imm32 offset fails its sanity checks, or the vtable slot
	// resolves outside steamclient.
	//
	// Caller-side caching is not required: this function maintains internal
	// function-local statics for the decoded offset and the (configStore, fn)
	// pair, so repeated calls are cheap. Intended to be invoked on Steam's
	// main thread from the IClientAppManager::LaunchApp hook.
	std::string forApp(uint32_t appId);

	// Whitespace/quote-bounded substring search. Returns true when `needle`
	// appears as a token inside `haystack` (matches the boundary logic used
	// by the execvpe argv search in LibraryInject's Proton backend).
	bool flagAppearsIn(const std::string& haystack, const std::string& needle);
}
