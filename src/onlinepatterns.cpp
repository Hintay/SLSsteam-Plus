#include "onlinepatterns.hpp"

#include "curl.hpp"
#include "log.hpp"
#include "patterns.hpp"   // for PATTERN_BAKED_HASH (extern, via patterns.gen.hpp)
#include "utils.hpp"

#include <toml++/toml.hpp>



namespace
{
	constexpr const char* kUrl =
		"https://raw.githubusercontent.com/AceSLS/SLSsteam/refs/heads/main/res/patterns.toml";

	MemHlp::SigFollowMode parseFollow(const std::string& s)
	{
		if (s == "Relative") return MemHlp::SigFollowMode::Relative;
		if (s == "PrologueUpwards") return MemHlp::SigFollowMode::PrologueUpwards;
		return MemHlp::SigFollowMode::None;
	}

	std::vector<uint8_t> parsePrologue(const std::string& hex)
	{
		const auto raw = MemHlp::patternToBytes(hex.c_str());
		std::vector<uint8_t> out;
		for (const auto b : raw)
			if (b >= 0) out.push_back(static_cast<uint8_t>(b));
		return out;
	}

	// Parse a version key: "current" → 0 (latest), numeric string → that version.
	// Returns false for unrecognisable keys (caller should skip).
	bool parseVersionKey(const std::string& key, uint32_t& outVersion)
	{
		if (key == "current") { outVersion = 0; return true; }
		try { outVersion = static_cast<uint32_t>(std::stoul(key)); return true; }
		catch (...) { return false; }
	}

	// Parse a pattern spec table. The "pattern" field is either a plain string
	// (single entry, maxVersion=0) or a sub-table with "current" + version keys.
	// Shared fields (follow, prologue) are read from the parent spec table.
	void parsePatternSpec(const toml::table& spec, const std::string& key,
	                      std::map<std::string, std::vector<OnlinePatterns::Entry>>& byName)
	{
		const auto follow = parseFollow(spec["follow"].value_or(std::string("None")));
		std::vector<uint8_t> prologue;
		if (auto p = spec["prologue"].value<std::string>())
			prologue = parsePrologue(*p);

		auto& vec = byName[key];

		if (auto s = spec["pattern"].value<std::string>())
		{
			vec.push_back({ *s, follow, prologue, 0 });
		}
		else if (auto* tbl = spec["pattern"].as_table())
		{
			for (const auto& [vk, vv] : *tbl)
			{
				auto sig = vv.value<std::string>();
				if (!sig) continue;
				uint32_t maxVer;
				if (!parseVersionKey(std::string(vk.str()), maxVer)) continue;
				vec.push_back({ *sig, follow, prologue, maxVer });
			}
		}
	}

	// Parse an IpcHash value. Scalar int → single hash (maxVersion=0).
	// Table with "current" + version keys → versioned hashes.
	void parseIpcHashValue(const toml::node& val, std::vector<VersionedHash>& vec)
	{
		if (auto v = val.value<int64_t>())
		{
			vec.push_back({ static_cast<uint32_t>(*v), 0 });
		}
		else if (auto* tbl = val.as_table())
		{
			for (const auto& [vk, vv] : *tbl)
			{
				auto h = vv.value<int64_t>();
				if (!h) continue;
				uint32_t maxVer;
				if (!parseVersionKey(std::string(vk.str()), maxVer)) continue;
				vec.push_back({ static_cast<uint32_t>(*h), maxVer });
			}
		}
	}
}

OnlinePatterns::Overrides OnlinePatterns::fetchAndParse()
{
	Overrides ov;

	std::string body;
	long status = 0;
	Curl::RequestOptions opt;
	opt.timeoutConnectMs = 3000;
	opt.timeoutTotalMs   = 5000;
	opt.httpsOnlyRedirects = true;
	const int rc = Curl::request("GET", kUrl, {}, "", body, status, opt);
	if (rc != 0 || status != 200 || body.empty())
	{
		g_pLog->debug("OnlinePatterns: fetch failed rc=%d status=%ld\n", rc, status);
		return ov;
	}

	try
	{
		if (Utils::sha256OfString(body) == std::string(PATTERN_BAKED_HASH))
		{
			g_pLog->debug("OnlinePatterns: online hash == baked, skipping\n");
			return ov;
		}
		auto root = toml::parse(body);

		if (auto* patterns = root["Patterns"].as_table())
		{
			for (const auto& [modKey, modVal] : *patterns)
			{
				const auto* mod = modVal.as_table();
				if (!mod) continue;
				for (const auto& [fnKey, fnVal] : *mod)
				{
					const std::string key(fnKey.str());
					if (auto* tbl = fnVal.as_table())
						parsePatternSpec(*tbl, key, ov.byName);
				}
			}
		}

		if (auto* ipcHashes = root["IpcHashes"].as_table())
		{
			for (const auto& [ifaceKey, ifaceVal] : *ipcHashes)
			{
				const std::string ifaceName(ifaceKey.str());
				const auto* methods = ifaceVal.as_table();
				if (!methods) continue;
				for (const auto& [mKey, mVal] : *methods)
				{
					const std::string fullKey = ifaceName + "::" + std::string(mKey.str());
					parseIpcHashValue(mVal, ov.ipcHashes[fullKey]);
				}
			}
		}

		ov.usable = true;
		g_pLog->info("OnlinePatterns: parsed %zu pattern entries, %zu ipc hashes\n",
			ov.byName.size(), ov.ipcHashes.size());
	}
	catch (...)
	{
		g_pLog->info("OnlinePatterns: parse failed, ignoring online file\n");
		ov.usable = false;
	}

	return ov;
}
