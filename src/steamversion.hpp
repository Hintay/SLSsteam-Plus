#pragma once

#include <cstdint>

namespace SteamVersion
{
	// Resolve nSteamVersion via libtier0_s.so's GetMiniDumpBuildID().
	// Returns 0 if the symbol is unavailable or not yet initialized.
	uint32_t get();
}
