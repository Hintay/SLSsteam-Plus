#pragma once

#include "mtvar.hpp"
#include "log.hpp"

#include <toml++/toml.hpp>

#include <cstdint>
#include <cstdio>
#include <pthread.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>


class CFileWatcher;

// Unified Steam Cloud strategy for unlocked games (replaces flat DisableCloud).
//   Disable  — turn Steam Cloud off for unlocked apps (no sync, hides badge).
//   Redirect — keep cloud on but redirect saves to a local store we manage.
//   Off      — leave Steam Cloud untouched.
enum class CloudMode { Disable, Redirect, Off };

class CConfig {
public:
	struct FakeGame_t
	{
		uint32_t appId = 0;
		std::string title;
	};

	class CDlcData
	{
	public:
		uint32_t parentId;
		std::unordered_map<uint32_t, std::string> dlcIds;
		//No default constructor, otherwise dlcData will complain that no matching one was found
		//without implementing it ourself anyway
	};

	bool __parseError = false;

	MTVariable<std::unordered_set<uint32_t>> appIds;
	MTVariable<std::unordered_set<uint32_t>> addedAppIds;
	MTVariable<std::unordered_map<uint32_t, CDlcData>> dlcData;
	MTVariable<std::unordered_map<uint32_t, uint64_t>> appTokens;
	MTVariable<std::unordered_set<uint32_t>> fakeOffline;
	MTVariable<std::unordered_map<uint32_t, uint32_t>> fakeAppIds;
	MTVariable<FakeGame_t> idleStatus;
	MTVariable<std::unordered_map<uint32_t, std::string>> gameTitles;
	MTVariable<std::unordered_map<uint32_t, uint32_t>> subscriptionTimestamps;

	// Config-file-origin baselines. reconcileIntoConfig recomputes addedAppIds =
	// configAddedAppIds ∪ lua ownedAppIds (and appTokens likewise) so lua
	// hot-REMOVAL propagates instead of a union-only merge that only adds.
	// MTVariable because loadSettings (config FileWatcher thread) WRITES these
	// while reconcileIntoConfig (lua FileWatcher thread) READS them.
	// NOTE: kept as yamlAddedAppIds/yamlAppTokens for ABI/API compat with callers.
	MTVariable<std::unordered_set<uint32_t>> yamlAddedAppIds;
	MTVariable<std::unordered_map<uint32_t, uint64_t>> yamlAppTokens;

	MTVariable<std::unordered_map<uint32_t, std::unordered_set<uint32_t>>> denuvoGames;

	MTVariable<bool> disableFamilyLock;
	MTVariable<bool> useWhiteList;
	MTVariable<bool> automaticFilter;
	MTVariable<bool> playNotOwnedGames;
	MTVariable<bool> packageInjection;
	MTVariable<bool> onlinePatterns;
	MTVariable<bool> notifications;
	MTVariable<bool> notifyInit;
	MTVariable<bool> api;
	MTVariable<CloudMode>    cloudMode;
	MTVariable<std::string>  cloudStorePath;
	MTVariable<bool> cloudShowHiddenUI;
	MTVariable<bool> blockTicketRequests;
	MTVariable<bool> offlineAchievementsSchema;
	MTVariable<std::string> fakeEmail;
	MTVariable<int32_t> fakeWalletBalance;
	MTVariable<unsigned int> logLevel;
	MTVariable<bool> extendedLogging;

	// Manifest request-code provider chain summary (display only; never read for behavior).
	// The chain is set from yaml `Manifest.Providers` via ManifestProvider::setProviders() at load.
	MTVariable<std::string> manifestProvider;
	// Manifest.UseLuaManifestOverrides: when false, keep Steam IPC's manifest gid
	// instead of applying lua setmanifestid(...) overrides.
	MTVariable<bool> useLuaManifestOverrides;
	// Manifest HTTP timeout knobs for libcurl. connect covers DNS/TCP/TLS setup;
	// total caps the whole request and should stay below RequestCode's wait window.
	MTVariable<uint32_t> manifestTimeoutConnectMs;
	MTVariable<uint32_t> manifestTimeoutTotalMs;
	// Keep the built-in manifest provider's curl handle alive across requests so
	// libcurl can reuse keep-alive connections and TLS sessions.
	MTVariable<bool> manifestReuseConnection;

	// Lua.Paths: optional list of extra directories to scan for .lua plugin files.
	// These are scanned after the built-in steam-root and user-config dirs.
	MTVariable<std::vector<std::string>> luaPaths;

	//Using incomplete class to avoid runtime linking errors
	CFileWatcher* watcher;

	~CConfig();

	std::string getDir();
	std::string getPath();
	bool createFile();
	void migrateConfig();
	bool init();
	// Spawn the config-file FileWatcher. Must be called from load() (after
	// steamclient.so is mapped — i.e. inside Steam's main() context, not from
	// la_preinit). pthread_create at la_preinit time produces threads that
	// don't survive into Steam main, leaving the watch thread silently dead.
	void startWatcher();
	void shutdown();

	bool loadSettings();

	template<typename T>
	T getSetting(const toml::table& tbl, const char* name, T defVal)
	{
		if constexpr (std::is_same_v<T, bool>)
		{
			auto v = tbl[name].value<bool>();
			if (!v) { g_pLog->debug("Config: %s not set, using default\n", name); return defVal; }
			return *v;
		}
		else if constexpr (std::is_integral_v<T>)
		{
			auto v = tbl[name].value<int64_t>();
			if (!v) { g_pLog->debug("Config: %s not set, using default\n", name); return defVal; }
			return static_cast<T>(*v);
		}
		else
		{
			auto v = tbl[name].value<std::string>();
			if (!v) { g_pLog->debug("Config: %s not set, using default\n", name); return defVal; }
			if constexpr (std::is_same_v<T, std::string>) return *v;
			else return T(*v);
		}
	}

	template<typename T>
	std::unordered_set<T> getList(const toml::table& tbl, const char* name)
	{
		std::unordered_set<T> list;
		auto* arr = tbl[name].as_array();
		if (!arr)
		{
			g_pLog->debug("Config: %s not set, using default\n", name);
			return list;
		}
		for (const auto& item : *arr)
		{
			if constexpr (std::is_integral_v<T>)
			{
				if (auto v = item.template value<int64_t>())
				{
					list.emplace(static_cast<T>(*v));
					if constexpr (std::is_same_v<T, uint32_t>)
						g_pLog->info("Added %u to %s\n", static_cast<uint32_t>(*v), name);
				}
				else { __parseError = true; }
			}
			else
			{
				if (auto v = item.template value<T>())
					list.emplace(*v);
				else { __parseError = true; }
			}
		}
		return list;
	}

	template<typename T, typename T2>
	std::unordered_map<T, T2> getMap(const toml::table& tbl, const char* name)
	{
		std::unordered_map<T, T2> map;
		auto* sub = tbl[name].as_table();
		if (!sub)
		{
			g_pLog->debug("Config: %s not set, using default\n", name);
			return map;
		}
		for (const auto& [k, v] : *sub)
		{
			try
			{
				T key;
				if constexpr (std::is_integral_v<T>)
					key = static_cast<T>(std::stoul(std::string(k.str())));
				else
					key = T(std::string(k.str()));

				T2 val;
				if constexpr (std::is_integral_v<T2>)
					val = static_cast<T2>(v.value_or(int64_t(0)));
				else
					val = v.value_or(T2{});

				map[key] = val;
			}
			catch (...) { __parseError = true; }
		}
		return map;
	}

	bool isAddedAppId(uint32_t appId);
	bool addAdditionalAppId(uint32_t appId);

	bool shouldExcludeAppId(uint32_t appId);
	uint32_t getDenuvoGameOwner(uint32_t appId);
};

extern CConfig g_config;
