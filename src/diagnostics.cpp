#include "diagnostics.hpp"

#include "globals.hpp"
#include "log.hpp"
#include "patterns.hpp"
#include "utils.hpp"
#include "version.gen.hpp"

#include "libmem/libmem.h"

#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

namespace
{
	std::mutex g_hashCacheMutex;
	std::unordered_map<std::string, std::string> g_hashCache;

	bool shouldLog(LogLevel lvl)
	{
		return static_cast<unsigned int>(lvl) >= static_cast<unsigned int>(CLog::getMinLevel());
	}

	const lm_module_t* moduleForPattern(const Pattern_t* pattern)
	{
		return pattern && pattern->module ? pattern->module : &g_modSteamClient;
	}

	const char* componentName(const lm_module_t* module)
	{
		if (module == &g_modSteamClient)
		{
			return "steamclient";
		}
		if (module == &g_modSteamUI)
		{
			return "steamui";
		}
		if (module && module->name[0])
		{
			return module->name;
		}
		return "unknown";
	}

	bool hashModule(const lm_module_t& module, std::string& out)
	{
		if (!module.path[0])
		{
			return false;
		}

		try
		{
			out = Utils::getFileSHA256(module.path);
			return true;
		}
		catch (...)
		{
			return false;
		}
	}

	std::string moduleCacheKey(const lm_module_t& module)
	{
		return module.path[0] ? module.path : componentName(&module);
	}

	bool cachedModuleHash(const lm_module_t* module, std::string& out)
	{
		if (!module)
		{
			return false;
		}

		const std::string key = moduleCacheKey(*module);
		{
			const auto lock = std::lock_guard(g_hashCacheMutex);
			auto it = g_hashCache.find(key);
			if (it != g_hashCache.end())
			{
				out = it->second;
				return true;
			}
		}

		std::string sha256;
		if (!hashModule(*module, sha256))
		{
			return false;
		}

		const auto lock = std::lock_guard(g_hashCacheMutex);
		const auto [it, inserted] = g_hashCache.emplace(key, sha256);
		(void)inserted;
		out = it->second;
		return true;
	}

	std::string displayModuleHash(const lm_module_t* module)
	{
		if (!module)
		{
			return "<unavailable>";
		}
		if (!module->path[0])
		{
			return "<no-path>";
		}

		std::string sha256;
		if (!cachedModuleHash(module, sha256))
		{
			return "<unavailable>";
		}
		return sha256;
	}

	void logModuleSummary(const char* component, const lm_module_t& module)
	{
		const std::string sha256 = displayModuleHash(&module);
		g_pLog->info
		(
			"Diagnostics: %s path=%s base=%p end=%p size=%zu sha256=%s\n",
			component,
			module.path,
			reinterpret_cast<void*>(module.base),
			reinterpret_cast<void*>(module.end),
			static_cast<size_t>(module.size),
			sha256.c_str()
		);
	}
}

bool Diagnostics::tryGetModuleSHA256(const lm_module_t& module, std::string& out)
{
	return cachedModuleHash(&module, out);
}

void Diagnostics::logStartupModuleSummary()
{
	if (!g_pLog || !shouldLog(LogLevel::Info))
	{
		return;
	}

	g_pLog->info("Diagnostics: SLSsteam version=%llu commit=%s\n", static_cast<unsigned long long>(VERSION), COMMIT_HASH);
	logModuleSummary("steamclient", g_modSteamClient);
	logModuleSummary("steamui", g_modSteamUI);
}

void Diagnostics::logPatternSummary()
{
	if (!g_pLog || (!shouldLog(LogLevel::Info) && !shouldLog(LogLevel::Debug)))
	{
		return;
	}

	size_t found = 0;
	size_t missing = 0;

	for (const auto* pattern : Patterns::registry())
	{
		if (!pattern)
		{
			continue;
		}

		const lm_module_t* module = moduleForPattern(pattern);
		if (pattern->address == LM_ADDRESS_BAD)
		{
			missing++;
			const std::string sha256 = displayModuleHash(module);
			g_pLog->info
			(
				"Diagnostics: pattern missing name=%s component=%s path=%s sha256=%s source=builtin-signature\n",
				pattern->name.c_str(),
				componentName(module),
				module ? module->path : "<unknown>",
				sha256.c_str()
			);
		}
		else
		{
			found++;
			g_pLog->debug
			(
				"Diagnostics: pattern ok name=%s component=%s address=%p source=builtin-signature\n",
				pattern->name.c_str(),
				componentName(module),
				reinterpret_cast<void*>(pattern->address)
			);
		}
	}

	g_pLog->info
	(
		"Diagnostics: pattern summary found=%zu missing=%zu total=%zu source=builtin-signature\n",
		found,
		missing,
		found + missing
	);
}
