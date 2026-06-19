#include "onlinepatterns.hpp"

#include "curl.hpp"
#include "log.hpp"
#include "patterns.hpp"   // for PATTERN_BAKED_HASH (extern, via patterns.gen.hpp)
#include "utils.hpp"

#include "yaml-cpp/yaml.h"



namespace
{
	constexpr const char* kUrl =
		"https://raw.githubusercontent.com/AceSLS/SLSsteam/refs/heads/main/res/patterns.yaml";

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

	uint32_t parseMaxVersion(const YAML::Node& node)
	{
		if (node && node.IsScalar())
			return static_cast<uint32_t>(node.as<unsigned long>());
		return 0;
	}

	OnlinePatterns::Entry parsePatternSpec(const YAML::Node& spec)
	{
		OnlinePatterns::Entry e;
		e.follow = parseFollow(spec["follow"] ? spec["follow"].as<std::string>() : "None");
		if (spec["prologue"]) e.prologue = parsePrologue(spec["prologue"].as<std::string>());
		e.maxVersion = parseMaxVersion(spec["max_version"]);
		for (const auto& c : spec["candidates"])
			e.candidates.push_back(c.as<std::string>());
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
		YAML::Node root = YAML::Load(body);
		if (root["Patterns"] && root["Patterns"].IsMap())
		for (const auto& mod : root["Patterns"])
		{
			for (const auto& fn : mod.second)
			{
				const std::string key = fn.first.as<std::string>();
				const YAML::Node val = fn.second;
				if (val.IsSequence())
				{
					const std::string effName = (val[0] && val[0]["name"])
						? val[0]["name"].as<std::string>() : key;
					auto& vec = ov.byName[effName];
					for (const auto& item : val)
						vec.push_back(parsePatternSpec(item));
				}
				else if (val.IsMap())
				{
					const std::string effName = val["name"] ? val["name"].as<std::string>() : key;
					ov.byName[effName].push_back(parsePatternSpec(val));
				}
			}
		}

		if (root["IpcHashes"] && root["IpcHashes"].IsMap())
		{
			for (const auto& iface : root["IpcHashes"])
			{
				const std::string ifaceName = iface.first.as<std::string>();
				for (const auto& m : iface.second)
				{
					const std::string mKey = ifaceName + "::" + m.first.as<std::string>();
					auto& vec = ov.ipcHashes[mKey];
					if (m.second.IsSequence())
					{
						for (const auto& item : m.second)
						{
							VersionedHash hc;
							if (item.IsMap())
							{
								hc.hash = static_cast<uint32_t>(item["hash"].as<unsigned long>());
								hc.maxVersion = parseMaxVersion(item["max_version"]);
							}
							else
							{
								hc.hash = static_cast<uint32_t>(item.as<unsigned long>());
							}
							vec.push_back(hc);
						}
					}
					else
					{
						vec.push_back({ static_cast<uint32_t>(m.second.as<unsigned long>()), 0 });
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
