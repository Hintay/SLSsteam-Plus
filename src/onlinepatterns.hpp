#pragma once

#include "memhlp.hpp"
#include "versiontypes.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace OnlinePatterns
{
	struct Entry
	{
		std::string pattern;
		MemHlp::SigFollowMode follow = MemHlp::SigFollowMode::None;
		std::vector<uint8_t> prologue;
		uint32_t maxVersion = 0;       // 0 = latest (no upper bound)
	};

	struct Overrides
	{
		bool usable = false;
		std::map<std::string, std::vector<Entry>> byName;
		std::map<std::string, std::vector<VersionedHash>> ipcHashes;
	};

	Overrides fetchAndParse();
}
