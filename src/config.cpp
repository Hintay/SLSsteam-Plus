#include "config.hpp"

#include "config_default.hpp"
#include "feats/package.hpp"
#include "filewatcher.hpp"
#include "log.hpp"
#include "lua/LuaLoader.hpp"
#include "lua/ManifestProvider.hpp"
#include "yaml-cpp/yaml.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <unordered_set>
#include <vector>


std::string CConfig::getDir()
{
	char pathBuf[255];
	const char* configDir = getenv("XDG_CONFIG_HOME"); //Most users should have this set iirc
	if (configDir != NULL)
	{
		sprintf(pathBuf, "%s/SLSsteam", configDir);
	}
	else
	{
		const char* home = getenv("HOME");
		sprintf(pathBuf, "%s/.config/SLSsteam", home);
	}

	return std::string(pathBuf);
}

std::string CConfig::getPath()
{
	return getDir().append("/config.yaml");
}

bool CConfig::createFile()
{
	std::string path = getPath();
	if (!std::filesystem::exists(path))
	{
		std::string dir = getDir();
		if (!std::filesystem::exists(dir))
		{
			if (!std::filesystem::create_directory(dir))
			{
				g_pLog->notify("Unable to create config directory at %s!\n", dir.c_str());
				return false;
			}

			g_pLog->debug("Created config directory at %s\n", dir.c_str());
		}

		FILE* file = fopen(path.c_str(), "w");
		if (!file)
		{
			g_pLog->notify("Unable to create config at %s!\n", path.c_str());
			return false;
		}

		fputs(defaultConfig, file);
		fflush(file);
		fclose(file);
	}

	return true;
}

static void onFileChange(const std::string& path, uint32_t mask)
{
	(void)path;
	(void)mask;
	g_config.loadSettings();
}

static void collectAppIdDelta(const std::unordered_set<uint32_t>& previous,
	const std::unordered_set<uint32_t>& current,
	std::vector<uint32_t>& additions,
	std::vector<uint32_t>& removals)
{
	for (uint32_t id : current)
	{
		if (!previous.contains(id)) additions.push_back(id);
	}

	for (uint32_t id : previous)
	{
		if (!current.contains(id)) removals.push_back(id);
	}
}

bool CConfig::init()
{
	if(createFile())
	{
		watcher = new CFileWatcher(onFileChange);
		watcher->addFile(getPath().c_str());
		watcher->start();
	}

	loadSettings();
	return true;
}

CConfig::~CConfig()
{
	shutdown();
}

void CConfig::shutdown()
{
	if (watcher)
	{
		delete watcher;
		watcher = nullptr;
	}
}

void CConfig::setError(ELoadError err)
{
	if (__loadErrors.get() > err)
	{
		return;
	}

	__loadErrors = err;
}

bool CConfig::loadSettings()
{
	const bool queueLiveAppIdChanges = LuaLoader::initDone();
	const auto previousAddedAppIds = queueLiveAppIdChanges
		? addedAppIds.get()
		: std::unordered_set<uint32_t>();

	YAML::Node node;
	try
	{
		node = YAML::LoadFile(getPath());
	}
	catch (YAML::BadFile& bf)
	{
		g_pLog->notifyLong("Can not read config.yaml! %s\nUsing defaults", bf.msg.c_str());
		node = YAML::Node(); //Create empty node and let defaults kick in
	}
	catch (YAML::ParserException& pe)
	{
		g_pLog->notifyLong("Error parsing config.yaml! %s\nUsing defaults", pe.msg.c_str());
		node = YAML::Node(); //Create empty node and let defaults kick in
	}

	__loadErrors = ELoadError::None;
	
	disableFamilyLock = getSetting<bool>(node, "DisableFamilyShareLock", true);
	useWhiteList = getSetting<bool>(node, "UseWhitelist", false);
	automaticFilter = getSetting<bool>(node, "AutoFilterList", true);
	playNotOwnedGames = getSetting<bool>(node, "PlayNotOwnedGames", false);
	packageInjection = getSetting<bool>(node, "PackageInjection", true);
	onlinePatterns = getSetting<bool>(node, "OnlinePatterns", true);
	notifications = getSetting<bool>(node, "Notifications", true);
	notifyInit = getSetting<bool>(node, "NotifyInit", true);
	api = getSetting<bool>(node, "API", true);
	fakeEmail = getSetting<std::string>(node, "FakeEmail", "");
	fakeWalletBalance = getSetting<int32_t>(node, "FakeWalletBalance", 0);
	disableCloud = getSetting<bool>(node, "DisableCloud", true);
	achievementsSchemaProbeNoConnection = getSetting<bool>(node, "AchievementsSchemaProbeNoConnection", false);
	extendedLogging = getSetting<bool>(node, "ExtendedLogging", false);
	logLevel = getSetting<unsigned int>(node, "LogLevel", 2);

	//TODO: Create smart logging function to log them automatically via getSetting
	g_pLog->info("DisableFamilyShareLock: %i\n", disableFamilyLock.get());
	g_pLog->info("UseWhitelist: %i\n", useWhiteList.get());
	g_pLog->info("AutoFilterList: %i\n", automaticFilter.get());
	g_pLog->info("PlayNotOwnedGames: %i\n", playNotOwnedGames.get());
	g_pLog->info("PackageInjection: %i\n", packageInjection.get());
	g_pLog->info("OnlinePatterns: %i\n", onlinePatterns.get());
	g_pLog->info("Notifications: %i\n", notifications.get());
	g_pLog->info("NotifyInit: %i\n", notifyInit.get());
	g_pLog->info("API: %i\n", api.get());
	g_pLog->info("FakeEmail: %s\n", fakeEmail.get().c_str());
	g_pLog->info("FakeWalletBalance: %i\n", fakeWalletBalance.get());
	g_pLog->info("DisableCloud: %i\n", disableCloud.get());
	g_pLog->info("AchievementsSchemaProbeNoConnection: %i\n", achievementsSchemaProbeNoConnection.get());
	g_pLog->info("ExtendedLogging: %i\n", extendedLogging.get());
	g_pLog->info("LogLevel: %i\n", logLevel.get());

	appIds = getList<uint32_t>(node, "AppIds");
	fakeOffline = getList<uint32_t>(node, "FakeOffline");

	fakeAppIds = getMap<uint32_t, uint32_t>(node, "FakeAppIds");
	gameTitles = getMap<uint32_t, std::string>(node, "GameTitles");
	subscriptionTimestamps = getMap<uint32_t, uint32_t>(node, "SubscriptionTimestamps");

	// AdditionalApps + AppTokens carry a yaml baseline that reconcileIntoConfig()
	// unions the live lua tables onto. Parse them into locals and record the yaml
	// baseline first (supports lua hot-removal, not just union add).
	const auto yamlAdditional = getList<uint32_t>(node, "AdditionalApps");
	const auto yamlTokens     = getMap<uint32_t, uint64_t>(node, "AppTokens");
	yamlAddedAppIds = yamlAdditional;
	yamlAppTokens   = yamlTokens;

	// Atomic-replace guard for the FileWatcher hot-reload window: when reconcile runs
	// (queueLiveAppIdChanges) it performs the single locked addedAppIds/appTokens =
	// yaml ∪ lua write below, so the live sets transition old→new in one step and are
	// never transiently narrowed to the yaml-only subset. A narrowed set would briefly
	// drop lua addappid ids, flipping isControlledApp and thus per-app cloud/ownership
	// decisions mid-reload. On initial load (lua not up yet, reconcile gated off)
	// assign the yaml set directly.
	if (!queueLiveAppIdChanges)
	{
		addedAppIds = yamlAdditional;
		appTokens   = yamlTokens;
	}

	//Do not warn for these (yet?)
	const auto idleStatusNode = node["IdleStatus"];
	if (idleStatusNode)
	{
		try
		{
			auto appId = idleStatusNode["AppId"].as<uint32_t>();
			auto title = idleStatusNode["Title"].as<std::string>();

			idleStatus = FakeGame_t
			{
				appId,
				title
			};

			g_pLog->info("Idle status %s with AppId %u\n", title.c_str(), appId);
		}
		catch(...)
		{
			//g_pLog->warn("Failed to parse IdleStatus!");A
			setError(ELoadError::ParsingException);
		}
	}

	const auto dlcDataNode = node["DlcData"];
	if(dlcDataNode)
	{
		auto _dlcData = dlcData.empty();

		for(auto& app : dlcDataNode)
		{
			try
			{
				const uint32_t parentId = app.first.as<uint32_t>();

				CDlcData data;
				data.parentId = parentId;
				g_pLog->info("Adding DlcData for %u\n", parentId);

				for(auto& dlc : app.second)
				{
					const uint32_t dlcId = dlc.first.as<uint32_t>();
					//There's more efficient types to store strings, but they mostly do not work
					const std::string dlcName = dlc.second.as<std::string>();

					data.dlcIds[dlcId] = dlcName;
					g_pLog->info("DlcId %u -> %s\n", dlcId, dlcName.c_str());
				}

				_dlcData[parentId] = data;
			}
			catch(...)
			{
				//g_pLog->notify("Failed to parse DlcData!");
				setError(ELoadError::ParsingException);
				break;
			}
		}

		dlcData = _dlcData;
	}
	else
	{
		//g_pLog->notify("Missing DlcData entry in config!");
		setError(ELoadError::MissingKey);
	}

	const auto denuvoGamesNode = node["DenuvoGames"];
	if (denuvoGamesNode)
	{
		auto _denuvoGames = denuvoGames.empty();

		for (auto& steamIdNode : denuvoGamesNode)
		{
			try
			{
				const uint32_t steamId = steamIdNode.first.as<uint32_t>();
				_denuvoGames[steamId] = std::unordered_set<uint32_t>();

				for (auto& appIdNode : steamIdNode.second)
				{
					const uint32_t appId = appIdNode.as<uint32_t>();
					_denuvoGames[steamId].emplace(appId);

					//Again, not loggin SteamId because of privacy
					g_pLog->info("Added DenuvoGame %u\n", appId);
				}
			}
			catch (...)
			{
				//g_pLog->notify("Failed to parse DenuvoGames!");
				setError(ELoadError::ParsingException);
			}
		}

		denuvoGames.set(_denuvoGames);
	}
	else
	{
		//g_pLog->notify("Missing DenuvoGames entry in config!");
		setError(ELoadError::MissingKey);
	}

	// Manifest — optional nested section. Manifest.Providers selects the request-code provider
	// chain (scalar or list; see below), passed to ManifestProvider::setProviders() after load.
	// If absent/empty, restore the default chain (opensteamtool -> wudrm -> steamrun), which makes
	// config hot-reload behave the same as a fresh start.
	{
		const auto manifestNode = node["Manifest"];
		std::vector<std::string> providerList;
		bool useLuaOverrides = true;
		uint32_t timeoutConnectMs = 5000;
		uint32_t timeoutTotalMs = 10000;
		bool reuseConnection = true;
		// Manifest.Providers — the ordered request-code provider chain. Accepts either a single
		// scalar (`Providers: wudrm`) or a list (`Providers: [opensteamtool, wudrm, steamrun]`).
		if (manifestNode && manifestNode["Providers"])
		{
			try
			{
				const auto pnode = manifestNode["Providers"];
				if (pnode.IsSequence())
					for (const auto& n : pnode) providerList.push_back(n.as<std::string>());
				else if (pnode.IsScalar())
					providerList.push_back(pnode.as<std::string>());
			}
			catch (...)
			{
				// A bad element (e.g. a nested node where a scalar is expected) throws mid-loop; discard
				// the half-parsed prefix so we fall back to the default chain instead of silently
				// applying a truncated one.
				providerList.clear();
				setError(ELoadError::ParsingException);
			}
		}
		if (manifestNode && manifestNode["UseLuaManifestOverrides"])
		{
			try
			{
				useLuaOverrides = manifestNode["UseLuaManifestOverrides"].as<bool>();
			}
			catch (...)
			{
				setError(ELoadError::ParsingException);
			}
		}
		if (manifestNode && manifestNode["TimeoutConnectMs"])
		{
			try
			{
				timeoutConnectMs = manifestNode["TimeoutConnectMs"].as<uint32_t>();
			}
			catch (...)
			{
				setError(ELoadError::ParsingException);
			}
		}
		if (manifestNode && manifestNode["TimeoutTotalMs"])
		{
			try
			{
				timeoutTotalMs = manifestNode["TimeoutTotalMs"].as<uint32_t>();
			}
			catch (...)
			{
				setError(ELoadError::ParsingException);
			}
		}
		if (manifestNode && manifestNode["ReuseConnection"])
		{
			try
			{
				reuseConnection = manifestNode["ReuseConnection"].as<bool>();
			}
			catch (...)
			{
				setError(ELoadError::ParsingException);
			}
		}
		useLuaManifestOverrides = useLuaOverrides;
		manifestTimeoutConnectMs = timeoutConnectMs;
		manifestTimeoutTotalMs = timeoutTotalMs;
		manifestReuseConnection = reuseConnection;
		g_pLog->info("Manifest.UseLuaManifestOverrides: %i\n", useLuaManifestOverrides.get());
		g_pLog->info("Manifest.TimeoutsMs: connect=%u total=%u\n",
			manifestTimeoutConnectMs.get(), manifestTimeoutTotalMs.get());
		g_pLog->info("Manifest.ReuseConnection: %i\n", manifestReuseConnection.get());
		// Apply the configured chain; absent/empty Providers restores the default all-built-ins chain.
		// Keep the full chain in g_config.manifestProvider for diagnostics/display only; behavior reads
		// ManifestProvider's active chain directly.
		if (providerList.empty())
			ManifestProvider::resetProviders();
		else
			ManifestProvider::setProviders(providerList);
		manifestProvider = ManifestProvider::activeProviderChainSummary();
	}

	// Lua.Paths — optional list of extra directories to scan for .lua plugin files.
	// Missing or empty section is silently ignored (no setError — it is optional).
	{
		const auto luaNode = node["Lua"];
		std::vector<std::string> paths;
		if (luaNode && luaNode["Paths"])
		{
			for (const auto& entry : luaNode["Paths"])
			{
				try
				{
					paths.push_back(entry.as<std::string>());
				}
				catch (...)
				{
					setError(ELoadError::ParsingException);
				}
			}
		}
		luaPaths = paths;
		if (!paths.empty())
		{
			g_pLog->info("Lua.Paths: %zu extra dir(s) configured\n", paths.size());
		}
	}

	switch(__loadErrors.get())
	{
		case ELoadError::MissingKey:
			g_pLog->notify("Issues during config loading encountered! Missing key(s)");
			break;
		case ELoadError::ParsingException:
			g_pLog->notify("Issues during config loading encountered! Parsing error(s)");
			break;

		default:
			break;
	}

	// Perform the single atomic addedAppIds/appTokens = yaml ∪ lua write. This matters
	// on FileWatcher hot-reload, where loadSettings() re-runs but LuaLoader::init()
	// does NOT — without this, lua-only appIds would vanish from g_config until a
	// restart. The yaml baseline was parsed into yamlAddedAppIds/yamlAppTokens above
	// but the live sets were intentionally NOT narrowed to it (see the atomic-replace
	// guard), so on hot-reload this update is the sole writer of the live sets.
	//
	// Gate on initDone(): before init() finishes its tables are empty (so this was
	// a no-op anyway) AND being written on the load thread, so a FileWatcher
	// hot-reload merging here would race that construction. After init() it is safe
	// (the tables are frozen, read-only).
	if (queueLiveAppIdChanges)
	{
		LuaLoader::reconcileIntoConfig();

		const auto currentAddedAppIds = addedAppIds.get();
		std::vector<uint32_t> additions;
		std::vector<uint32_t> removals;
		collectAppIdDelta(previousAddedAppIds, currentAddedAppIds, additions, removals);
		Package::queueAppIdChanges(additions, removals);
	}

	return true;
}

bool CConfig::isAddedAppId(uint32_t appId)
{
	return addedAppIds.contains(appId);
}

bool CConfig::shouldExcludeAppId(uint32_t appId)
{
	bool exclude = false;
	//Proper way would be with getAppType, but that seems broken so we need to do this instead
	constexpr uint32_t ONE_BILLION = 1E9; //Implicit cast from double to unsigned int, hopefully this does not break anything
	if (appId >= ONE_BILLION) //Higher and equal to 10^9 gets used by Steam Internally
	{
		exclude = true;
	}
	else
	{
		bool found = appIds.contains(appId);
		exclude = !isAddedAppId(appId) && ((useWhiteList.get() && !found) || (!useWhiteList.get() && found));
	}

	g_pLog->once("shouldExcludeAppId(%u) -> %i\n", appId, exclude);
	return exclude;
}

uint32_t CConfig::getDenuvoGameOwner(uint32_t appId)
{
	for(const auto& tpl : denuvoGames.get())
	{
		if (tpl.second.contains(appId))
		{
			//g_pLog->once("%u is DenuvoGame\n", appId);
			return tpl.first;
		}
	}

	return 0;
}

CConfig g_config = CConfig();
