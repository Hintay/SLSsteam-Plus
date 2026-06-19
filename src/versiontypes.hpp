#pragma once

#include <cstdint>
#include <vector>

// Shared version-selection types used by both online pattern overrides and
// IpcOutbound hash resolution. Kept in a lightweight header to avoid pulling
// memhlp / libmem / log into every consumer.

struct VersionedHash
{
	uint32_t hash;
	uint32_t maxVersion = 0;   // 0 = latest (no upper bound)
};

// Pick the best item from a versioned list for a given Steam version.
// Returns nullptr if no entry covers `ver`.
//   - Prefers the entry with the SMALLEST maxVersion >= ver.
//   - maxVersion == 0 (latest) is the catch-all, used only when no bounded entry matches.
//   - When ver == 0 (version unavailable), returns nullptr (caller should fall back to trying all).
template <typename T>
const T* pickByVersion(const std::vector<T>& items, uint32_t ver,
                       uint32_t T::*mvField = &T::maxVersion)
{
	if (ver == 0)
		return nullptr;

	const T* best = nullptr;
	for (const auto& item : items)
	{
		const uint32_t mv = item.*mvField;
		if (mv == 0)
		{
			if (!best || best->*mvField != 0)
				best = &item;
		}
		else if (mv >= ver)
		{
			if (!best || best->*mvField == 0 || mv < best->*mvField)
				best = &item;
		}
	}
	return best;
}
