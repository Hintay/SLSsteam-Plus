#include "patterns.hpp"
#include "config.hpp"
#include "driftreport.hpp"
#include "globals.hpp"
#include "ipchash.gen.hpp"
#include "ipcoutbound.hpp"
#include "log.hpp"
#include "onlinepatterns.hpp"
#include "steamversion.hpp"
#include "versiontypes.hpp"

std::vector<Pattern_t*>& Patterns::registry()
{
	static std::vector<Pattern_t*> patterns;
	return patterns;
}

Pattern_t::Pattern_t(const char* name, std::string pattern,
                     MemHlp::SigFollowMode followMode, std::vector<uint8_t> prologue,
                     lm_module_t* module, bool optional)
	: name(name), pattern(std::move(pattern)), followMode(followMode),
	  prologue(std::move(prologue)), optional(optional), module(module),
	  address(LM_ADDRESS_BAD)
{
	Patterns::registry().emplace_back(this);
}

bool Pattern_t::find()
{
	return findWith(pattern, followMode, prologue);
}

bool Pattern_t::findWith(const std::string& sig,
                         MemHlp::SigFollowMode mode, const std::vector<uint8_t>& prologueBytes)
{
	lm_module_t& mod = module ? *module : g_modSteamClient;
	address = MemHlp::searchSignature(
		name.c_str(), sig.c_str(), mod, mode,
		const_cast<uint8_t*>(prologueBytes.data()), prologueBytes.size());
	if (address == LM_ADDRESS_BAD)
		return false;
	if (address >= mod.base && address < mod.base + mod.size)
		return true;
	g_pLog->warn("Patterns: %s resolved %p outside module, rejecting\n",
		name.c_str(), reinterpret_cast<void*>(address));
	address = LM_ADDRESS_BAD;
	return false;
}

bool Patterns::init()
{
	std::vector<Pattern_t*> failed, optionalFailed;
	for (auto& p : Patterns::registry())
	{
		if (p->find())
			continue;
		(p->optional ? optionalFailed : failed).push_back(p);
	}

	bool needsOnline = !failed.empty() || !optionalFailed.empty();
	if (!needsOnline)
	{
		for (const auto h : IpcHash::kAllBaked)
		{
			if (!IpcOutbound::hasHash(h))
			{
				g_pLog->info("Patterns: baked funcHash 0x%08x not found in .text, fetching online\n", h);
				needsOnline = true;
				break;
			}
		}
	}

	if (needsOnline && g_config.onlinePatterns.get())
	{
		// Keep online recovery synchronous so Hooks::setup() sees recovered
		// addresses. The fetch itself is isolated in a short-lived self-helper
		// process, avoiding parent-process DNS/NSS dlopen while la_objopen holds
		// ld.so's loader lock.
		const auto ov = OnlinePatterns::fetchAndParse();
		if (ov.usable)
		{
			if (!ov.ipcHashes.empty())
				IpcOutbound::setOnlineHashes(ov.ipcHashes);

			if (!failed.empty() || !optionalFailed.empty())
			{
				g_pLog->info("Patterns: %zu required + %zu optional unresolved, trying online override\n",
					failed.size(), optionalFailed.size());
				const uint32_t ver = SteamVersion::get();
				const auto retryOnline = [&ov, ver](std::vector<Pattern_t*>& list)
				{
					std::vector<Pattern_t*> still;
					for (auto* p : list)
					{
						auto it = ov.byName.find(p->name);
						if (it == ov.byName.end()) { still.push_back(p); continue; }
						const auto& entries = it->second;

						bool recovered = false;
						const OnlinePatterns::Entry* tried = pickByVersion(entries, ver);
						if (tried)
							recovered = p->findWith(tried->pattern, tried->follow, tried->prologue);

						if (!recovered)
							for (const auto& e : entries)
								if (&e != tried && (recovered = p->findWith(e.pattern, e.follow, e.prologue)))
									break;

						if (recovered)
							g_pLog->info("Patterns: %s recovered online\n", p->name.c_str());
						else
							still.push_back(p);
					}
					list.swap(still);
				};
				retryOnline(failed);
				retryOnline(optionalFailed);
			}
		}
	}

	// Surface remaining misses through the consolidated drift report. Recovered
	// patterns (whether builtin-resolved or online-recovered) are not pushed.
	for (const auto* p : failed)
		DriftReport::pushUnresolvedPattern(p->name.c_str(), false);
	for (const auto* p : optionalFailed)
		DriftReport::pushUnresolvedPattern(p->name.c_str(), true);

	return failed.empty();
}
