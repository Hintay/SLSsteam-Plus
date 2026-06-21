#pragma once

#include <cstdint>

namespace StatsClient
{
	// Query stats.opensteamtool.com/{appId} for a recommended donor SteamID.
	// Returns true and writes *outSteamId on success; false on API disabled,
	// network error, or invalid response. Results are cached in-process.
	// Safe to call from any thread including coroutine contexts — the HTTP
	// request runs on a dedicated worker thread with adequate stack space.
	bool fetchStatSteamId(uint32_t appId, uint64_t* outSteamId);
}
