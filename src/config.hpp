#pragma once

#include "mtvar.hpp"
#include "log.hpp"

#include "yaml-cpp/exceptions.h"
#include "yaml-cpp/node/node.h"
#include "yaml-cpp/yaml.h"

#include <cstdint>
#include <cstdio>
#include <pthread.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>


class CFileWatcher;

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

	enum class ELoadError : uint32_t
	{
		None,
		MissingKey,
		ParsingException
	};
	MTVariable<ELoadError> __loadErrors;

	MTVariable<std::unordered_set<uint32_t>> appIds;
	MTVariable<std::unordered_set<uint32_t>> addedAppIds;
	MTVariable<std::unordered_map<uint32_t, CDlcData>> dlcData;
	MTVariable<std::unordered_map<uint32_t, uint64_t>> appTokens;
	MTVariable<std::unordered_set<uint32_t>> fakeOffline;
	MTVariable<std::unordered_map<uint32_t, uint32_t>> fakeAppIds;
	MTVariable<FakeGame_t> idleStatus;
	MTVariable<std::unordered_map<uint32_t, std::string>> gameTitles;
	MTVariable<std::unordered_map<uint32_t, uint32_t>> subscriptionTimestamps;

	// yaml-origin baselines. reconcileIntoConfig recomputes addedAppIds =
	// yamlAddedAppIds ∪ lua ownedAppIds (and appTokens likewise) so lua
	// hot-REMOVAL propagates instead of a union-only merge that only adds.
	// MTVariable because loadSettings (config FileWatcher thread) WRITES these
	// while reconcileIntoConfig (lua FileWatcher thread) READS them.
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
	MTVariable<bool> disableCloud;
	MTVariable<bool> achievementsSchemaProbeNoConnection;
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
	bool init();
	void shutdown();

	void setError(ELoadError err);
	bool loadSettings();

	template<typename T>
	T getSetting(YAML::Node& node, const char* name, T defVal)
	{
		if (!node[name])
		{
			//g_pLog->notifyLong("Missing %s in configfile! Using default", name);
			setError(ELoadError::MissingKey);
			return defVal;
		}

		try
		{
			 return node[name].as<T>();
		}
		catch (YAML::BadConversion& er)
		{
			//g_pLog->notify("Failed to parse value of %s! Using default\n", name);
			setError(ELoadError::ParsingException);
			return defVal;
		}
	};

	template<typename T>
	std::unordered_set<T> getList(YAML::Node& rootNode, const char* name)
	{
		auto list = std::unordered_set<T>();

		const auto node = rootNode[name];
		if (!node)
		{
			//g_pLog->notifyLong("Missing %s in configfile! Using default", name);
			setError(ELoadError::MissingKey);
			return list;
		}

		for(auto subNode : node)
		{
			try
			{
				T val = subNode.as<T>();
				list.emplace(val);

				//TODO: Find better way to log shit
				if (std::is_same_v<T, uint32_t>)
				{
					g_pLog->info("Added %u to %s\n", val, name);
				}
			}
			catch(...)
			{
				//g_pLog->notify("Failed to parse %s!", name);
				setError(ELoadError::ParsingException);
			}
		}

		return list;
	}

	template<typename T, typename T2>
	std::unordered_map<T, T2> getMap(YAML::Node& rootNode, const char* name)
	{
		auto map = std::unordered_map<T, T2>();

		const auto node = rootNode[name];
		if (!node)
		{
			//g_pLog->notifyLong("Missing %s in configfile! Using default", name);
			setError(ELoadError::MissingKey);
			return map;
		}

		for(auto& subNode : node)
		{
			try
			{
				//TODO: Add error checks for failed parsing since yaml-cpp does not throw
				auto k = subNode.first.as<T>();
				auto v = subNode.second.as<T2>();

				map[k] = v;

				if (std::is_same_v<T, uint32_t> && std::is_same_v<T, T2>)
				{
					g_pLog->info("Added %u to %u in %s\n", k, v, name);
				}
				else if (std::is_same_v<T, uint32_t> && std::is_same_v<T2, uint64_t>)
				{
					g_pLog->info("Added %u to %llu in %s\n", k, v, name);
				}
			}
			catch(...)
			{
				//g_pLog->notify("Failed to parse %s!", name);
				setError(ELoadError::ParsingException);
			}
		}

		return map;
	}

	bool isAddedAppId(uint32_t appId);
	bool addAdditionalAppId(uint32_t appId);

	bool shouldExcludeAppId(uint32_t appId);
	uint32_t getDenuvoGameOwner(uint32_t appId);
};

extern CConfig g_config;
