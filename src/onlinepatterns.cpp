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

	OnlinePatterns::Entry parsePatternSpec(const toml::table& spec)
	{
		OnlinePatterns::Entry e;
		e.follow = parseFollow(spec["follow"].value_or(std::string("None")));
		if (auto p = spec["prologue"].value<std::string>())
			e.prologue = parsePrologue(*p);
		e.maxVersion = static_cast<uint32_t>(spec["max_version"].value_or(int64_t(0)));
		if (auto* cands = spec["candidates"].as_array())
			for (const auto& c : *cands)
				if (auto s = c.value<std::string>())
					e.candidates.push_back(*s);
		return e;
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
					if (auto* arr = fnVal.as_array())
					{
						// Array of specs — effective name comes from first element's "name" field
						std::string effName = key;
						if (!arr->empty())
							if (auto* first = arr->front().as_table())
								if (auto n = (*first)["name"].value<std::string>())
									effName = *n;
						auto& vec = ov.byName[effName];
						for (const auto& item : *arr)
							if (auto* t = item.as_table())
								vec.push_back(parsePatternSpec(*t));
					}
					else if (auto* tbl = fnVal.as_table())
					{
						// Single spec table
						std::string effName = key;
						if (auto n = (*tbl)["name"].value<std::string>())
							effName = *n;
						ov.byName[effName].push_back(parsePatternSpec(*tbl));
					}
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
					auto& vec = ov.ipcHashes[fullKey];
					if (auto* arr = mVal.as_array())
					{
						for (const auto& item : *arr)
						{
							VersionedHash hc;
							if (auto* t = item.as_table())
							{
								hc.hash = static_cast<uint32_t>((*t)["hash"].value_or(int64_t(0)));
								hc.maxVersion = static_cast<uint32_t>((*t)["max_version"].value_or(int64_t(0)));
							}
							else
							{
								hc.hash = static_cast<uint32_t>(item.value_or(int64_t(0)));
							}
							vec.push_back(hc);
						}
					}
					else
					{
						vec.push_back({ static_cast<uint32_t>(mVal.value_or(int64_t(0))), 0 });
					}
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
