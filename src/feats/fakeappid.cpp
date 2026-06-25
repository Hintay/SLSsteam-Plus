#include "fakeappid.hpp"

#include "apps.hpp"
#include "launch_options.hpp"

#include "../config.hpp"
#include "../log.hpp"

#include "../sdk/CProtoBufMsgBase.hpp"
#include "../sdk/CSteamEngine.hpp"
#include "../sdk/CSteamMatchmakingServers.hpp"
#include "../sdk/CUser.hpp"
#include "../sdk/IClientUtils.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>

namespace
{
	uint64_t serverAddressKey(const servernetadr_t& address)
	{
		static_assert(sizeof(address) == sizeof(uint64_t));
		uint64_t key = 0;
		std::memcpy(&key, &address, sizeof(key));
		return key;
	}
}

uint32_t FakeAppIds::lastAppLaunched;

std::unordered_map<uint32_t, uint32_t> FakeAppIds::fakeAppIdMap = std::unordered_map<uint32_t, uint32_t>();
std::unordered_map<uint32_t, uint32_t> FakeAppIds::fakeAppIdMapServer = std::unordered_map<uint32_t, uint32_t>();
std::unordered_map<uint64_t, uint32_t> FakeAppIds::fakeAppIdMapPings = std::unordered_map<uint64_t, uint32_t>();

namespace
{
	// Runtime real→fake overrides registered by FakeAppIds::onLaunchApp when a
	// [[FakeAppIds.Flags]] rule matches. Consulted by getFakeAppId() ahead of
	// the static [FakeAppIds] map. Mutex-protected because the hot read path
	// (CSteamEngine pipe runs, CMsgClientGamesPlayed send) lands on Steam IPC
	// threads while the write path is the LaunchApp hook on Steam's main thread.
	std::mutex g_runtimeFakeMu;
	std::unordered_map<uint32_t, uint32_t> g_runtimeFakeAppIds;
}

uint32_t FakeAppIds::getFakeAppId(uint32_t appId)
{
	{
		std::lock_guard<std::mutex> lock(g_runtimeFakeMu);
		auto it = g_runtimeFakeAppIds.find(appId);
		if (it != g_runtimeFakeAppIds.end()) return it->second;
	}

	auto fakeAppIds = g_config.fakeAppIds.get();

	if (fakeAppIds.contains(appId))
	{
		return fakeAppIds[appId];
	}
	else if (fakeAppIds.contains(0) && !Apps::isGenuinelySubscribed(appId))
	{
		return fakeAppIds[0];
	}

	return 0;
}

uint32_t FakeAppIds::getRealAppIdForCurrentPipe(bool fallback)
{
	auto* pPipe = g_pClientUtils->getPipeIndex();
	if (!pPipe) return 0;
	uint32_t hPipe = *pPipe;
	if (fakeAppIdMap.contains(hPipe))
	{
		return fakeAppIdMap[hPipe];
	}

	if (fallback)
	{
		return g_pClientUtils->getAppId();
	}

	return 0;
}

void FakeAppIds::launchApp(uint32_t appId)
{
	lastAppLaunched = appId;
}

void FakeAppIds::onLaunchApp(uint32_t appId)
{
	const auto rules = g_config.fakeAppIdFlags.get();

	// Always clear any prior runtime mapping for this appId so a re-launch
	// without the flag falls back through to the static map.
	{
		std::lock_guard<std::mutex> lock(g_runtimeFakeMu);
		g_runtimeFakeAppIds.erase(appId);
	}

	if (rules.empty()) return;

	// Skip the LaunchOptions read if no rule could possibly apply (every rule
	// has either an Apps allowlist that excludes appId or an ExcludeApps that
	// includes it).
	const bool anyApplicable = std::any_of(rules.begin(), rules.end(),
		[appId](const CConfig::FakeAppIdFlagRule& r) {
			if (!r.apps.empty() && !r.apps.contains(appId)) return false;
			if (r.excludeApps.contains(appId)) return false;
			return !r.flag.empty();
		});
	if (!anyApplicable) return;

	const std::string launchOpts = LaunchOptions::forApp(appId);
	if (launchOpts.empty()) return;

	for (const auto& rule : rules) {
		if (rule.flag.empty() || !rule.fakeAppId) continue;
		if (!rule.apps.empty() && !rule.apps.contains(appId)) continue;
		if (rule.excludeApps.contains(appId)) continue;
		if (!LaunchOptions::flagAppearsIn(launchOpts, rule.flag)) continue;

		{
			std::lock_guard<std::mutex> lock(g_runtimeFakeMu);
			g_runtimeFakeAppIds[appId] = rule.fakeAppId;
		}
		g_pLog->info("FakeAppIds: appId %u -> %u (Flag=\"%s\" from LaunchOptions)\n",
			appId, rule.fakeAppId, rule.flag.c_str());
		return;
	}
}

void FakeAppIds::setAppIdForCurrentPipe(uint32_t& appId)
{
	//Keep track of every AppId, for various reasons
	//fakeAppIdMap[*g_pClientUtils->getPipeIndex()] = appId;
	auto* pPipeSet = g_pClientUtils->getPipeIndex();
	if (!pPipeSet) return;
	fakeAppIdMap[*pPipeSet] = lastAppLaunched;

	g_pLog->debug("fakeAppIdMap[%p] = %u\n", *pPipeSet, appId);

	//Do not change Steam Client itself (AppId 0)
	if (!appId)
	{
		return;
	}

	uint32_t newAppId = getFakeAppId(appId);
	if (newAppId)
	{
		g_pLog->once("Changing AppId of %u\n", appId);
		appId = newAppId;
	}
}

void FakeAppIds::runIPCFrame(bool post)
{
	uint32_t appId = getRealAppIdForCurrentPipe(false);
	uint32_t fakeAppId = getFakeAppId(appId);

	if (!appId || !fakeAppId || appId == fakeAppId)
	{
		return;
	}

	if (post)
	{
		appId = fakeAppId;
	}

	auto* pPipeRun = g_pClientUtils->getPipeIndex();
	g_pLog->debug("Setting AppId to %u in pipe %p\n", appId, pPipeRun ? *pPipeRun : 0u);
	g_pSteamEngine->setAppIdForCurrentPipe(appId);
}

void FakeAppIds::getServerDetails(uint32_t handle, gameserverdetails_t& details)
{
	if (!fakeAppIdMapServer.contains(handle))
	{
		return;
	}

	const uint32_t realAppId = fakeAppIdMapServer[handle];

	fakeAppIdMapPings[serverAddressKey(details.address)] = realAppId;
	details.appId = realAppId;

	g_pLog->debug("Changing appId back to %u\n", realAppId);
}

uint32_t FakeAppIds::requestInternetServerList(uint32_t appId)
{
	const uint32_t fake = getFakeAppId(appId);
	if (!fake)
	{
		return 0;
	}

	g_pLog->debug("Replacing %u with %u\n", appId, fake);
	return fake;
}

void FakeAppIds::pingResponse(gameserverdetails_t *details)
{
	if (!details)
	{
		return;
	}

	const uint64_t ip = serverAddressKey(details->address);
	if (!fakeAppIdMapPings.contains(ip))
	{
		return;
	}

	details->appId = fakeAppIdMapPings[ip];
}


void FakeAppIds::sendMsg(CProtoBufMsgBase* msg)
{
	switch(msg->type)
	{
		case EMSG_GAMESPLAYED:
		case EMSG_GAMESPLAYED_NO_DATABLOB:
		case EMSG_GAMESPLAYED_WITH_DATABLOB:
			break;

		default:
			return;
	}

	const auto body = msg->getBody<CMsgClientGamesPlayed>();
	for(int i = 0; i < body->games_played_size(); i++)
	{
		const auto game = body->mutable_games_played(i);
		const uint32_t fakeAppId = FakeAppIds::getFakeAppId(game->game_id());
		if (!fakeAppId)
		{
			continue;
		}

		g_pLog->debug("Setting %llu to %u\n", game->game_id(), fakeAppId);
		game->set_game_id(fakeAppId);
	}
}
