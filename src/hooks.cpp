#include "hooks.hpp"

#include "api.hpp"
#include "config.hpp"
#include "globals.hpp"
#include "log.hpp"
#include "memhlp.hpp"
#include "patterns.hpp"
#include "ipchash.gen.hpp"
#include "ipcoutbound.hpp"
#include "ipcdispatch.hpp"

#include "sdk/CAppOwnershipInfo.hpp"
#include "sdk/CProtoBufMsgBase.hpp"
#include "sdk/CSteamEngine.hpp"
#include "sdk/CSteamMatchmakingServers.hpp"
#include "sdk/CUser.hpp"
#include "sdk/EReleaseState.hpp"
#include "sdk/EResult.hpp"
#include "sdk/IClientAppManager.hpp"
#include "sdk/IClientApps.hpp"
#include "sdk/IClientUtils.hpp"

#include "feats/achievements.hpp"
#include "feats/apps.hpp"
#include "feats/depotkey.hpp"
#include "feats/dlc.hpp"
#include "feats/manifest.hpp"
#include "feats/misc.hpp"
#include "feats/fakeappid.hpp"
#include "feats/package.hpp"
#include "feats/steamui.hpp"
#include "feats/requestcode.hpp"
#include "feats/ticket.hpp"
#include "feats/forge_ticket.hpp"

#include "ownership.hpp"

#include "lua/LuaLoader.hpp"

#include "sdk/CNetPacket.hpp"
#include "sdk/PackageInfo.hpp"

#include "libmem/libmem.h"

#include <atomic>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <pthread.h>
#include <strings.h>
#include <unistd.h>
#include <vector>


template<typename T>
Hook<T>::Hook(const char* name)
{
	this->name = std::string(name);
}

template<typename T>
DetourHook<T>::DetourHook(const char* name) : Hook<T>::Hook(name)
{
	this->size = 0;
}

//TODO: Fix this ungodly mess
template<typename T>
DetourHook<T>::DetourHook() : DetourHook<T>("")
{

}

template<typename T>
VFTHook<T>::VFTHook(const char* name) : Hook<T>::Hook(name)
{
	this->hooked = false;
}

template<typename T>
bool DetourHook<T>::setup(const Pattern_t& pattern, T hookFn)
{
	if (pattern.address == LM_ADDRESS_BAD)
	{
		return false;
	}

	this->name = pattern.name;
	this->originalFn.address = pattern.address;
	this->hookFn.fn = hookFn;

	return true;
}

template<typename T>
void DetourHook<T>::place()
{
	this->size = LM_HookCode(this->originalFn.address, this->hookFn.address, &this->tramp.address);
	MemHlp::fixPICThunkCall(this->name.c_str(), this->originalFn.address, this->tramp.address);

	g_pLog->debug
	(
		"Detour hooked %s (%p) with hook at %p and tramp at %p\n",
		this->name.c_str(),
		this->originalFn.address,
		this->hookFn.address,
		this->tramp.address
	);
}

template<typename T>
void DetourHook<T>::remove()
{
	if (!this->size)
	{
		return;
	}

	LM_UnhookCode(this->originalFn.address, this->tramp.address, this->size);
	this->size = 0;

	g_pLog->debug("Unhooked %s\n", this->name.c_str());
}

template<typename T>
void VFTHook<T>::place()
{
	LM_VmtHook(this->vft.get(), this->index, this->hookFn.address);
	this->hooked = true;

	g_pLog->debug
	(
		"VFT hooked %s (%p) with hook at %p\n",
		this->name.c_str(),
		this->originalFn.address,
		this->hookFn.address
	);
}

template<typename T>
void VFTHook<T>::remove()
{
	//No clue how libmem reacts when unhooking a non existent hook
	//so we do this
	if (!this->hooked)
	{
		return;
	}

	LM_VmtUnhook(this->vft.get(), this->index);
	this->hooked = false;

	g_pLog->debug("Unhooked %s!\n", this->name.c_str());
}

template<typename T>
void VFTHook<T>::setup(std::shared_ptr<lm_vmt_t> vft, unsigned int index, T hookFn)
{
	this->vft = vft;
	this->index = index;

	this->originalFn.address = LM_VmtGetOriginal(this->vft.get(), this->index);
	this->hookFn.fn = hookFn;
}

namespace {
	constexpr std::ptrdiff_t kSteamAppStateFlagsOffset = 0x4;
	constexpr std::ptrdiff_t kSteamAppIdOffset = 0x8;

	bool isConfiguredChildAppForParent(const std::unordered_map<uint32_t, CConfig::CDlcData>& dlcData, uint32_t appId, uint32_t childAppId)
	{
		if (!childAppId)
		{
			return false;
		}

		const auto it = dlcData.find(appId);
		return it != dlcData.end() && it->second.dlcIds.contains(childAppId);
	}

	bool isLuaExplicitDepotDependency(const DepotEntry& entry)
	{
		return !LuaLoader::getKey(entry.DepotId).empty()
			|| (entry.AppId && LuaLoader::hasOwnedAppId(entry.AppId))
			|| (entry.DlcAppId && LuaLoader::hasOwnedAppId(entry.DlcAppId));
	}

	bool isYamlConfiguredDepotDependency(const std::unordered_map<uint32_t, CConfig::CDlcData>& dlcData, uint32_t appId, const DepotEntry& entry)
	{
		return (entry.AppId && Ownership::isYamlAdditionalApp(entry.AppId))
			|| (entry.DlcAppId && Ownership::isYamlAdditionalApp(entry.DlcAppId))
			|| isConfiguredChildAppForParent(dlcData, appId, entry.AppId)
			|| isConfiguredChildAppForParent(dlcData, appId, entry.DlcAppId);
	}

	bool shouldFilterYamlConfiguredDepot(const std::unordered_map<uint32_t, CConfig::CDlcData>& dlcData, uint32_t appId, const DepotEntry& entry)
	{
		return isYamlConfiguredDepotDependency(dlcData, appId, entry)
			&& !isLuaExplicitDepotDependency(entry);
	}

	void filterYamlConfiguredDepots(const char* label, uint32_t appId, void* pDepotInfo)
	{
		if (!pDepotInfo)
		{
			return;
		}

		auto* depotInfo = reinterpret_cast<CUtlVector<DepotEntry>*>(pDepotInfo);
		DepotEntry* entries = depotInfo->m_Memory.m_pMemory;
		const int32_t size = depotInfo->m_Size;
		if (!entries || size <= 0 || static_cast<uint32_t>(size) > depotInfo->m_Memory.m_nAllocationCount)
		{
			return;
		}

		const auto dlcData = g_config.dlcData.get();
		int32_t writeIdx = 0;
		int32_t removed = 0;
		for (int32_t readIdx = 0; readIdx < size; ++readIdx)
		{
			DepotEntry& entry = entries[readIdx];
			if (shouldFilterYamlConfiguredDepot(dlcData, appId, entry))
			{
				++removed;
				g_pLog->once
				(
					"BuildDepotDependency(%u,%s) filtered YAML-configured depot: depot=%u owner_app=%u dlc=%u gid=%llu.\n",
					appId,
					label,
					entry.DepotId,
					entry.AppId,
					entry.DlcAppId,
					(unsigned long long)entry.ManifestGid
				);
				continue;
			}

			if (writeIdx != readIdx)
			{
				entries[writeIdx] = entry;
			}
			++writeIdx;
		}

		if (removed)
		{
			if (writeIdx <= 0)
			{
				g_pLog->once("BuildDepotDependency(%u,%s) would filter all %i depot entries; keeping original list because Steam treats an empty dependency vector as a fallback signal.\n", appId, label, size);
				return;
			}

			depotInfo->m_Size = writeIdx;
			g_pLog->once("BuildDepotDependency(%u,%s) filtered %i YAML-configured depot entries, kept %i/%i.\n", appId, label, removed, writeIdx, size);
		}
	}
}

__attribute__((hot))
static void hkTraceIPC(const char* iface, const char* fn)
{
	Hooks::TraceIPC.tramp.fn(iface, fn);

	if (g_config.extendedLogging.get())
	{
		g_pLog->debug
		(
			"%s(%s, %s)\n",

			Hooks::TraceIPC.name.c_str(),
			iface,
			fn
		);
	}
}

static int hkLoadDepotDecryptionKey(void* pObject, uint32_t foo, char* KeyName, char* Key, uint32_t KeySize)
{
	// Generic KV value reader: Steam calls it for many keys, so only act on a
	// depot decryption-key read and fall through for everything else. KeyName is
	// "Software\\Valve\\Steam\\Depots\\<depotId>\\DecryptionKey"; Key is a direct
	// output buffer of KeySize bytes (observed 128) and the function returns the
	// number of bytes written.
	if (KeyName)
	{
		const char* tag = strstr(KeyName, "\\DecryptionKey");
		if (tag && tag > KeyName)
		{
			// [idStart, tag) spans the decimal <depotId> between two backslashes.
			const char* idStart = tag;
			while (idStart > KeyName && idStart[-1] != '\\')
			{
				--idStart;
			}

			uint32_t depotId = 0;
			const auto [end, ec] = std::from_chars(idStart, tag, depotId);
			if (ec == std::errc{} && end == tag)
			{
				const int written = DepotKey::provideKey(depotId, Key, KeySize);
				if (written > 0)
				{
					return written;
				}
			}
		}
	}

	return Hooks::LoadDepotDecryptionKey.tramp.fn(pObject, foo, KeyName, Key, KeySize);
}

static bool hkBuildDepotDependency(void* pUserAppMgr, uint32_t appId, void* pUserConfig, void* pDepotInfo, void* pSharedDepotInfo, void* pSteamApp, uint32_t* pBuildId, bool* pbBetaFallback)
{
	const bool ret = Hooks::BuildDepotDependency.tramp.fn(pUserAppMgr, appId, pUserConfig, pDepotInfo, pSharedDepotInfo, pSteamApp, pBuildId, pbBetaFallback);
	// Do not empty YAML-only dependency vectors here; Steam treats empty vectors as a fallback signal.
	if (Ownership::isYamlOnlyAdditionalApp(appId))
	{
		g_pLog->once("BuildDepotDependency(%u) left YAML-only app depot list unchanged; update/install entry points are responsible for blocking downloads.\n", appId);
	}
	else
	{
		filterYamlConfiguredDepots("depot", appId, pDepotInfo);
		filterYamlConfiguredDepots("shared", appId, pSharedDepotInfo);
	}

	if (pDepotInfo)
	{
		Manifest::patchDepotInfo(reinterpret_cast<CUtlVector<DepotEntry>*>(pDepotInfo));
	}

	return ret;
}

static bool hkBUpdateAppDownloadPlan(void* pSteamApp, void* pAppManagerInner, bool flag)
{
	if (pSteamApp)
	{
		uint32_t stateFlags = 0;
		uint32_t appId = 0;
		std::memcpy(&stateFlags, static_cast<const char*>(pSteamApp) + kSteamAppStateFlagsOffset, sizeof(stateFlags));
		std::memcpy(&appId, static_cast<const char*>(pSteamApp) + kSteamAppIdOffset, sizeof(appId));

		if (Ownership::isYamlOnlyAdditionalApp(appId))
		{
			g_pLog->once
			(
				"BUpdateAppDownloadPlan(%u) blocked YAML-only app update/download planning: app_state_flags=0x%x flag=%i.\n",
				appId,
				stateFlags,
				flag
			);
			return false;
		}
	}

	return Hooks::BUpdateAppDownloadPlan.tramp.fn(pSteamApp, pAppManagerInner, flag);
}

static uint32_t hkCAPIJob_GetPlayerStats(void* pAPIJob)
{
	uint32_t res = Hooks::CAPIJob_GetPlayerStats.tramp.fn(pAPIJob);

	g_pLog->debug
	(
		"%s(%p) -> %i\n",
		Hooks::CAPIJob_GetPlayerStats.name.c_str(),
		pAPIJob,
		res
	);

	Achievements::getPlayerStats(res);

	return res;
}

static void hkProtoBufMsgBase_InitFromPacket(CProtoBufMsgBase* pMsg, void* pSrc)
{
	Hooks::CProtoBufMsgBase_InitFromPacket.tramp.fn(pMsg, pSrc);

	//Safety first
	if (!pSrc)
	{
		return;
	}

	g_pLog->debug("Received ProtoBufMsg of type %u with type %s\n", pMsg->type, MemHlp::getTypeName(pMsg));

	Misc::recvMsg(pMsg);
	Ticket::recvMsg(pMsg);
}

static uint32_t hkProtoBufMsgBase_Send(CProtoBufMsgBase* pMsg)
{
	Apps::sendMsg(pMsg);
	FakeAppIds::sendMsg(pMsg);

	const uint32_t ret = Hooks::CProtoBufMsgBase_Send.tramp.fn(pMsg);
	g_pLog->debug("Sending ProtoBufMsg of type %u with type %s\n", pMsg->type, MemHlp::getTypeName(pMsg));

	return ret;
}

__attribute__((hot))
static bool hkCWebSocketConnection_BBuildAndAsyncSendFrame(void* pThis, int opcode, uint8_t* pubData, uint32_t cubData)
{
	// opcode 0x2 == WebSocket binary frame (the raw Steam packet payload; 0x2 is the
	// RFC6455 binary opcode — the runbook's "0x8" was an unrelated CLOSE call-site).
	// Both consumers are wrapped in catch(...) so a C++ exception can never unwind
	// through this C trampoline (would std::terminate).
	if (opcode == 0x2)
	{
		// requestcode: returns true for the GetManifestRequestCode ServiceMethod call
		// — DROP the frame (never sent to the CM); its response is fabricated + injected
		// on the recv path.
		bool drop = false;
		try { drop = RequestCode::onSendFrame(pubData, cubData); }
		catch (...) { drop = false; }
		if (drop)
			return true;

		// ownership tickets: CProtoBufMsgBase::Send must still run because Steam's
		// protobuf send path has internal state/lifetime side effects. Drop only at
		// the serialized WebSocket frame layer to avoid message_lite CHECK failures.
		try { drop = Ticket::onSendFrame(pubData, cubData); }
		catch (...) { drop = false; }
		if (drop)
			return true;

		// achievements: returns true only when it supplies a replacement packet. False
		// means achievements did not handle the frame; the fallback below sends the
		// original packet unchanged. Schema sha probes intentionally use that fallback.
		const uint8_t* newData = nullptr;
		uint32_t newSize = 0;
		bool replace = false;
		try { replace = Achievements::onSendFrame(pubData, cubData, newData, newSize); }
		catch (...) { replace = false; }
		if (replace)
		{
			if (!newData || !newSize)
				return true;
			return Hooks::CWebSocketConnection_BBuildAndAsyncSendFrame.tramp.fn(pThis, opcode, const_cast<uint8_t*>(newData), newSize);
		}
	}
	return Hooks::CWebSocketConnection_BBuildAndAsyncSendFrame.tramp.fn(pThis, opcode, pubData, cubData);
}

__attribute__((hot))
static void* hkCCMConnection_RecvPkt(void* pThis, CNetPacket* pPacket)
{
	// If a dropped GetManifestRequestCode's code fetch has completed, deliver the
	// fabricated ServiceMethodResponse by borrowing this incoming packet as a carrier
	// for one extra oRecvPkt call, then restore and deliver the real packet below.
	if (pPacket)
	{
		const uint8_t* injData = nullptr;
		uint32_t injSize = 0;
		bool inject = false;
		// catch(...) so a C++ exception can never unwind through this C trampoline.
		try { inject = RequestCode::nextInjection(injData, injSize); }
		catch (...) { inject = false; }
		if (inject)
		{
			uint8_t* origData = pPacket->m_pubData;
			uint32_t origSize = pPacket->m_cubData;
			pPacket->m_pubData = const_cast<uint8_t*>(injData);
			pPacket->m_cubData = injSize;
			Hooks::CCMConnection_RecvPkt.tramp.fn(pThis, pPacket);
			pPacket->m_pubData = origData;
			pPacket->m_cubData = origSize;
		}

		injData = nullptr;
		injSize = 0;
		inject = false;
		try { inject = Achievements::nextInjection(injData, injSize); }
		catch (...) { inject = false; }
		if (inject)
		{
			uint8_t* origData = pPacket->m_pubData;
			uint32_t origSize = pPacket->m_cubData;
			pPacket->m_pubData = const_cast<uint8_t*>(injData);
			pPacket->m_cubData = injSize;
			Hooks::CCMConnection_RecvPkt.tramp.fn(pThis, pPacket);
			pPacket->m_pubData = origData;
			pPacket->m_cubData = origSize;
		}

		// achievements: for a matching Player.GetUserStats response (147) or legacy
		// GetUserStatsResponse (819), clear stats + force eresult OK in place before
		// the original processes the packet. catch(...) guards the C trampoline.
		try { Achievements::onRecvPacket(pPacket); }
		catch (...) {}
	}
	return Hooks::CCMConnection_RecvPkt.tramp.fn(pThis, pPacket);
}

static void hkSteamEngine_Init(void* pSteamEngine)
{
	Hooks::CSteamEngine_Init.tramp.fn(pSteamEngine);

	g_pSteamEngine = reinterpret_cast<CSteamEngine*>(pSteamEngine);
	g_pLog->once("g_pSteamEngine at %p\n", pSteamEngine);
}

static uint32_t hkSteamEngine_SetAppIdForCurrentPipe(void* pSteamEngine, uint32_t appId, bool a2)
{
	FakeAppIds::setAppIdForCurrentPipe(appId);

	const uint32_t ret = Hooks::CSteamEngine_SetAppIdForCurrentPipe.tramp.fn(pSteamEngine, appId, a2);

	g_pLog->debug
	(
		"%s(%p, %u, %i) -> %i\n",

		Hooks::CSteamEngine_SetAppIdForCurrentPipe.name.c_str(),
		pSteamEngine,
		appId,
		a2,
		ret
	);

	return ret;
}

static gameserverdetails_t* hkSteamMatchmakingServers_GetServerDetails(void* pSteamMatchmakingServers, uint32_t handle, uint32_t serverIdx)
{
	gameserverdetails_t* ret = Hooks::CSteamMatchmakingServers_GetServerDetails.tramp.fn(pSteamMatchmakingServers, handle, serverIdx);

	g_pLog->debug
	(
		"%s(%p, %p, %u) -> %p\n",

		Hooks::CSteamMatchmakingServers_GetServerDetails.name.c_str(),
		pSteamMatchmakingServers,
		handle,
		serverIdx,
		ret
	);

	if(ret)
	{
		FakeAppIds::getServerDetails(handle, *ret);
	}

	return ret;
}

static uint32_t hkSteamMatchmakingServers_RequestInternetServerList(void* pSteamMatchmakingServers, uint32_t appId, uint32_t a2, uint32_t a3, uint32_t a4)
{
	const uint32_t fake = FakeAppIds::requestInternetServerList(appId);

	uint32_t handle = Hooks::CSteamMatchmakingServers_RequestInternetServerList.tramp.fn(pSteamMatchmakingServers, fake ? fake : appId, a2, a3, a4);

	g_pLog->debug
	(
		"%s(%p, %u, %p, %p, %p)->%p\n",

		Hooks::CSteamMatchmakingServers_RequestInternetServerList.name.c_str(),
		pSteamMatchmakingServers,
		appId,
		a2,
		a3,
		a4,
		handle
	);

	FakeAppIds::fakeAppIdMapServer[handle] = appId;

	return handle;
}

__attribute__((hot))
static uint32_t hkUser_CheckAppOwnership(void* pClientUser, uint32_t appId, CAppOwnershipInfo* pOwnershipInfo)
{
	// Capture CUser* once; setCUser is idempotent/atomic so calling every invocation is safe.
	Package::setCUser(pClientUser);

	const uint32_t ret = Hooks::CUser_CheckAppOwnership.tramp.fn(pClientUser, appId, pOwnershipInfo);

	// Pump only after the original ownership query has returned. Running Mark/Process before
	// the original can re-enter Steam's license path while it is still evaluating this query.
	Package::pumpOnSteamThread("CUser::CheckAppOwnership");   // initial inject + drain lua hot-reload changes, on this Steam thread

	//Do not log pOwnershipInfo because it gets deleted very quickly, so it's pretty much useless in the logs
	g_pLog->once
	(
		"%s(%p, %u) -> %i\n",

		Hooks::CUser_CheckAppOwnership.name.c_str(),
		pClientUser,
		appId,
		ret
	);

	// Refresh the genuine-owned cache from Steam's original ownership path before
	// SLSsteam's spoofers mutate pOwnershipInfo. This keeps false positives from
	// sticking for the whole session.
	if (pOwnershipInfo && Ownership::isControlledApp(appId))
	{
		const bool genuine = ret && pOwnershipInfo->existInPackageNums > 1;
		Ownership::setGenuinelyOwned(appId, genuine);
		if (genuine)
		{
			pOwnershipInfo->releaseState = ERELEASESTATE_RELEASED;
			return ret;
		}
	}

	if (Apps::checkAppOwnership(appId, pOwnershipInfo) || DLC::checkAppOwnership(appId, pOwnershipInfo))
	{
		return true;
	}

	return ret;
}

static uint32_t hkUser_GetSubscribedApps(void* pClientUser, uint32_t* pAppList, uint32_t size, uint8_t a3)
{
	uint32_t count = Hooks::CUser_GetSubscribedApps.tramp.fn(pClientUser, pAppList, size, a3);

	// This path is a more reliable Steam-thread touchpoint than CheckAppOwnership on some
	// SteamUI flows. Keep it post-original for the same re-entrancy reason as above.
	Package::setCUser(pClientUser);
	Package::pumpOnSteamThread("CUser::GetSubscribedApps");

	Apps::getSubscribedApps(pAppList, size, count);

	g_pLog->debug
	(
		"%s(%p, %p, %i, %i) -> %i\n",

		Hooks::CUser_GetSubscribedApps.name.c_str(),
		pClientUser,
		pAppList,
		size,
		a3,
		count
	);

	return count;
}

__attribute__((hot))
static void* hkCPackageInfo_GetPackageInfo(void* pThis, uint32_t pkgId, uint64_t token)
{
	void* ret = Hooks::CPackageInfo_GetPackageInfo.tramp.fn(pThis, pkgId, token);
	// pkg0 is a stable singleton. Capture once, only when
	// Available (Status==0), so we never latch a transient/invalid object.
	if (pkgId == 0 && ret && PackageInfo::status(ret) == 0)
	{
		Package::setInjectedPackage(ret);
		// pkg0 capture and the GetSubscribedApps pump touchpoint don't overlap in time:
		// GetSubscribedApps fires in a burst at boot (capturing CUser) then goes quiet,
		// while GetPackageInfo(0) keeps firing afterwards. Pump here too — this is the
		// touchpoint that provides pkg0, and CUser is already captured by now — so the
		// one-shot injection actually completes. Runs on a Steam thread; ThreadPumpGuard
		// makes the re-entrancy from ProcessPendingLicenseUpdates safe.
		Package::pumpOnSteamThread("CPackageInfo::GetPackageInfo");
	}
	return ret;
}

__attribute__((hot))
static void* hkCSteamUI_GetAppByID(void* pController, uint32_t appId, bool bCreate)
{
	SteamUI::setController(pController);
	return Hooks::CSteamUIAppController_GetAppByID.tramp.fn(pController, appId, bCreate);
}

__attribute__((hot))
static void hkCUpdateManager_MarkAppChange(void* pSource, uint32_t appId, uint32_t flags)
{
	SteamUI::setAppChangeSource(pSource);
	Hooks::CUpdateManager_MarkAppChange.tramp.fn(pSource, appId, flags);
}

// Stamp lua PurchasedTime into the app overview for controlled apps (desktop classic UI).
// arg3 is void** ppHolder (pointer-to-holder); deref once for the CSteamApp.
// Returns void* so EAX passes through unchanged regardless of the real return type.
// Note: fires 0 times on Deck gamescope/CEF — expected and harmless.
static void* hkCSteamUI_FillInAppOverview(void* pController, void* pAppOverview, void** ppHolder)
{
	SteamUI::stampPurchaseTimeIfControlled(ppHolder);
	return Hooks::CSteamUIAppController_FillInAppOverview.tramp.fn(pController, pAppOverview, ppHolder);
}

static bool hkClientAppManager_BCanRemotePlayTogether(void* pClientAppManager, uint32_t appId)
{
	const bool ret = Hooks::IClientAppManager_BCanRemotePlayTogether.tramp.fn(pClientAppManager, appId);
	g_pLog->debug
	(
		"%s(%p, %u) -> %u\n",
		Hooks::IClientAppManager_BCanRemotePlayTogether.name.c_str(),
		pClientAppManager,
		appId,
		ret
	);

	return true;
}

static void* hkClientAppManager_LaunchApp(void* pClientAppManager, uint32_t* pAppId, void* a2, void* a3, void* a4)
{
	if (pAppId)
	{
		g_pLog->once
		(
			"%s(%p, %u, %p, %p, %p)\n",

			Hooks::IClientAppManager_LaunchApp.name.c_str(),
			pClientAppManager,
			*pAppId,
			a2,
			a3,
			a4
		);

		FakeAppIds::launchApp(*pAppId);
		Ticket::launchApp(*pAppId);
	}

	//Do not do anything in post! Otherwise App launching will break
	return Hooks::IClientAppManager_LaunchApp.originalFn.fn(pClientAppManager, pAppId, a2, a3, a4);
}

static bool hkClientAppManager_IsAppDlcInstalled(void* pClientAppManager, uint32_t appId, uint32_t dlcId)
{
	const bool ret = Hooks::IClientAppManager_IsAppDlcInstalled.originalFn.fn(pClientAppManager, appId, dlcId);
	g_pLog->once
	(
		"%s(%p, %u, %u) -> %i\n",

		Hooks::IClientAppManager_IsAppDlcInstalled.name.c_str(),
		pClientAppManager,
		appId,
		dlcId,
		ret
	);

	if (DLC::isAppDlcInstalled(dlcId))
	{
		return true;
	}

	return ret;
}

static bool hkClientAppManager_BIsDlcEnabled(void* pClientAppManager, uint32_t appId, uint32_t dlcId, void* a3)
{
	const bool ret = Hooks::IClientAppManager_BIsDlcEnabled.originalFn.fn(pClientAppManager, appId, dlcId, a3);
	g_pLog->once
	(
		"%s(%p, %u, %u, %p) -> %i\n",

		Hooks::IClientAppManager_BIsDlcEnabled.name.c_str(),
		pClientAppManager,
		appId,
		dlcId,
		a3,
		ret
	);

	
	if (DLC::isDlcEnabled(appId))
	{
		return true;
	}

	return ret;
}

static bool hkClientAppManager_GetUpdateInfo(void* pClientAppManager, uint32_t appId, uint32_t* a2)
{
	const bool success = Hooks::IClientAppManager_GetAppUpdateInfo.originalFn.fn(pClientAppManager, appId, a2);
	g_pLog->once("IClientAppManager::GetUpdateInfo(%p, %u, %p) -> %i\n", pClientAppManager, appId, a2, success);

	if (Apps::shouldDisableUpdates(appId))
	{
		g_pLog->once("Disabled updates for %u\n", appId);
		return false;
	}

	return success;
}

// Install a VFThook at the slot located by its build-stable funcHash. NO hardcoded-index
// fallback: resolve the index from the funcHash and install only if found; on a miss, warn
// loudly and leave the hook uninstalled rather than risk patching the wrong slot.
template<typename T>
static void installVFTByFuncHash(VFTHook<T>& hook, const std::shared_ptr<lm_vmt_t>& vft, const char* name, uint32_t funcHash, T hk)
{
	const int idx = IpcOutbound::resolveIndex(name, funcHash);
	if (idx < 0)
	{
		g_pLog->warn("VFThook %s: funcHash 0x%08x not located in steamclient — hook NOT installed\n",
		             hook.name.c_str(), funcHash);
		return;
	}
	hook.setup(vft, static_cast<unsigned int>(idx), hk);
	hook.place();
}

__attribute__((hot))
static void hkClientAppManager_RunIPCFrame(void* pClientAppManager, void* a1, void* a2, void* a3)
{
	g_pClientAppManager = reinterpret_cast<IClientAppManager*>(pClientAppManager);

	static bool hooked = false;
	if (!hooked)
	{
		std::shared_ptr<lm_vmt_t> vft = std::make_shared<lm_vmt_t>();
		LM_VmtNew(*reinterpret_cast<lm_address_t**>(pClientAppManager), vft.get());

		installVFTByFuncHash(Hooks::IClientAppManager_BIsDlcEnabled,     vft, IpcHash::IClientAppManager::kBIsDlcEnabled_Name,     IpcHash::IClientAppManager::kBIsDlcEnabled,     hkClientAppManager_BIsDlcEnabled);
		installVFTByFuncHash(Hooks::IClientAppManager_GetAppUpdateInfo, vft, IpcHash::IClientAppManager::kGetUpdateInfo_Name,    IpcHash::IClientAppManager::kGetUpdateInfo,     hkClientAppManager_GetUpdateInfo);
		installVFTByFuncHash(Hooks::IClientAppManager_LaunchApp,        vft, IpcHash::IClientAppManager::kLaunchApp_Name,        IpcHash::IClientAppManager::kLaunchApp,         hkClientAppManager_LaunchApp);
		installVFTByFuncHash(Hooks::IClientAppManager_IsAppDlcInstalled, vft, IpcHash::IClientAppManager::kIsAppDlcInstalled_Name, IpcHash::IClientAppManager::kIsAppDlcInstalled, hkClientAppManager_IsAppDlcInstalled);

		g_pLog->debug("IClientAppManager->vft at %p\n", vft->vtable);
		hooked = true;
	}

	Hooks::IClientAppManager_RunIPCFrame.tramp.fn(pClientAppManager, a1, a2, a3);
	SLSAPI::runPendingInstallsOnAppManagerFrame();
}

static unsigned int hkClientApps_GetDLCCount(void* pClientApps, uint32_t appId)
{
	uint32_t count = Hooks::IClientApps_GetDLCCount.originalFn.fn(pClientApps, appId);
	g_pLog->once
	(
		"%s(%p, %u) -> %u\n",

		Hooks::IClientApps_GetDLCCount.name.c_str(),
		pClientApps,
		appId,
		count
	);
	
	appId = FakeAppIds::getRealAppIdForCurrentPipe();

	const uint32_t override = DLC::getDlcCount(appId);
	if (override)
	{
		return override;
	}

	return count;
}

static bool hkClientApps_GetDLCDataByIndex(void* pClientApps, uint32_t appId, int dlcIndex, uint32_t* pDlcId, bool* pIsAvailable, char* pChDlcName, size_t dlcNameLen)
{
	appId = FakeAppIds::getRealAppIdForCurrentPipe();

	//Preserve original call to populate stuff
	const bool ret = DLC::getDlcDataByIndex(appId, dlcIndex, pDlcId, pIsAvailable, pChDlcName, dlcNameLen)
		|| Hooks::IClientApps_GetDLCDataByIndex.originalFn.fn(pClientApps, appId, dlcIndex, pDlcId, pIsAvailable, pChDlcName, dlcNameLen);


	g_pLog->once
	(
		"%s(%p, %u, %i, %p, %p, %s, %i) -> %i\n",

		Hooks::IClientApps_GetDLCDataByIndex.name.c_str(),
		pClientApps,
		appId,
		dlcIndex,
		pDlcId,
		pIsAvailable,
		pChDlcName,
		dlcNameLen,
		ret
	);

	return ret;
}

__attribute__((hot))
static void hkClientApps_RunIPCFrame(void* pClientApps, void* a1, void* a2, void* a3)
{
	static bool hooked = false;
	if (!hooked)
	{
		g_pClientApps = reinterpret_cast<IClientApps*>(pClientApps);

		std::shared_ptr<lm_vmt_t> vft = std::make_shared<lm_vmt_t>();
		LM_VmtNew(*reinterpret_cast<lm_address_t**>(pClientApps), vft.get());

		installVFTByFuncHash(Hooks::IClientApps_GetDLCDataByIndex, vft, IpcHash::IClientApps::kGetDLCDataByIndex_Name, IpcHash::IClientApps::kGetDLCDataByIndex, hkClientApps_GetDLCDataByIndex);
		installVFTByFuncHash(Hooks::IClientApps_GetDLCCount,       vft, IpcHash::IClientApps::kGetDLCCount_Name,       IpcHash::IClientApps::kGetDLCCount,       hkClientApps_GetDLCCount);

		g_pLog->debug("IClientApps->vft at %p\n", vft->vtable);

		hooked = true;
	}

	Hooks::IClientApps_RunIPCFrame.tramp.fn(pClientApps, a1, a2, a3);
}

// ---- Zero-persist: strip controlled apps' cloudenabled from the cloud-synced sharedconfig.vdf ----
// SetCloudEnabledForApp must write cloudenabled into the roaming config store's KeyValues for the
// badge fix to work (the AutoCloud re-eval tree-walks the store). That store later serializes to
// userdata/<id>/7/remote/sharedconfig.vdf. We keep the in-memory store intact (badge stays fixed),
// but remove SLS-written cloudenabled blocks at the write boundary by filtering the serialized
// UserRoamingConfigStore buffer before Steam writes it.

// The exact set of appIds SLSsteam has written via SetCloudEnabledForApp this session. This is the
// authoritative "what we wrote" list used by the strip — far safer than re-deriving ownership at
// strip time (which races the genuine-ownership cache and would wrongly drop user toggles of owned
// games). The set is intentionally session-lifetime: once SLS has injected a cloudenabled=false
// value, later flushes keep stripping that SLS-origin value until Steam restarts.
static std::mutex                  g_cloudWroteMtx;
static std::unordered_set<uint32_t> g_cloudWroteApps;

// Snapshot the controlled-app set under a single lock. The strip tests membership against this local
// copy instead of locking per app-id line, and short-circuits the whole parse when the set is empty.
static std::unordered_set<uint32_t> snapshotCloudWroteApps()
{
	std::lock_guard<std::mutex> lk(g_cloudWroteMtx);
	return g_cloudWroteApps;
}

// --- offset-based VDF line helpers (operate directly on the serialized buffer, no allocation) ---
static size_t vdfLineEnd(const char* buf, size_t size, size_t s)
{
	while (s < size && buf[s] != '\n') ++s;
	return s;
}
// True if the line [s,e) is a single brace `br` (only whitespace around it).
static bool vdfLineIsBrace(const char* buf, size_t s, size_t e, char br)
{
	size_t a = s;
	while (a < e && (buf[a] == '\t' || buf[a] == ' ' || buf[a] == '\r')) ++a;
	if (a >= e || buf[a] != br) return false;
	++a;
	while (a < e && (buf[a] == '\t' || buf[a] == ' ' || buf[a] == '\r')) ++a;
	return a >= e;
}
// appId if the line [s,e) is a bare `\t*"<digits>"` key line (nothing else), else 0.
static uint32_t vdfLineAppId(const char* buf, size_t s, size_t e)
{
	size_t i = s;
	while (i < e && (buf[i] == '\t' || buf[i] == ' ')) ++i;
	if (i >= e || buf[i] != '"') return 0;
	++i;
	// Parse the digit run with from_chars (the uint32 convention already used in this file, ~L305):
	// it stops at the first non-digit and returns result_out_of_range for a >uint32 key, so an
	// overflowing 11+/large numeric key becomes a non-match (emitted verbatim) instead of wrapping
	// onto a real controlled appid.
	const char* const digitsStart = buf + i;
	uint32_t id = 0;
	const auto [end, ec] = std::from_chars(digitsStart, buf + e, id);
	if (ec != std::errc{} || end == digitsStart) return 0;
	i = static_cast<size_t>(end - buf);
	if (i >= e || buf[i] != '"') return 0;
	++i;
	while (i < e) { const char c = buf[i]; if (c != '\t' && c != ' ' && c != '\r') return 0; ++i; }
	return id;
}
static bool vdfLineIsCloudenabledKey(const char* buf, size_t s, size_t e)
{
	size_t i = s;
	while (i < e && (buf[i] == '\t' || buf[i] == ' ')) ++i;
	if (i >= e || buf[i] != '"') return false;
	++i;
	constexpr std::string_view key = "cloudenabled";
	if (e - i < key.size() + 1) return false;
	if (std::string_view(buf + i, key.size()) != key) return false;
	i += key.size();
	return i < e && buf[i] == '"';
}

// Filter a serialized UserRoamingConfigStore VDF buffer: remove controlled apps' cloudenabled.
// Brace-depth tracked, so an app block of any shape is handled (not just the 4-line cloudenabled-only
// case): a controlled "<id>" block that contains ONLY cloudenabled is dropped whole (no leftover
// appid in the cloud file); one that also has other keys keeps those, dropping only its cloudenabled
// line(s). Output is built by appending kept byte-ranges of the original buffer into `out` (a reused
// thread_local), so there is no per-line allocation. Returns true iff something was removed.
static bool stripControlledCloudFromBuffer(const char* buf, size_t size, std::string& out)
{
	out.clear();
	// Snapshot once: skip the entire parse when SLS has toggled nothing this session, and avoid
	// re-locking g_cloudWroteMtx for every app-id line in the (potentially hundreds-of-apps) tree.
	const std::unordered_set<uint32_t> wrote = snapshotCloudWroteApps();
	if (wrote.empty()) return false;
	bool changed = false;
	size_t i = 0;
	while (i < size)
	{
		const size_t s = i;
		const size_t e = vdfLineEnd(buf, size, s);
		const size_t next = (e < size) ? e + 1 : size;

		// This outer scan is line-by-line, not depth-scoped to the apps map, so a "<digits>" key
		// anywhere whose value is in `wrote` is a strip candidate. That stays safe because
		// (a) vdfLineAppId rejects out-of-range/overflowing numeric keys, (b) `wrote` holds only real
		// controlled appids, and (c) whole-block drop needs a cloudenabled-only block, which in a
		// roaming store only occurs under Software\Valve\Steam\apps.
		const uint32_t id = vdfLineAppId(buf, s, e);
		if (id && wrote.count(id))
		{
			const size_t bs = next;                              // expected "{" line
			const size_t be = vdfLineEnd(buf, size, bs);
			if (bs < size && vdfLineIsBrace(buf, bs, be, '{'))
			{
				const size_t bodyStart = (be < size) ? be + 1 : size;
				// Single pass: speculatively append the kept block (the "<id>" line, "{", every
				// non-cloudenabled line, and all braces) into `out`, tracking whether the block has
				// any non-cloudenabled content (hasOther) and whether a cloudenabled line was actually
				// dropped (hadCloud). At the matching "}" decide: keep the speculative output, roll it
				// back for a whole-block drop, or roll it back as malformed. `out.resize(mark)` only
				// rewinds the length (capacity is kept), so a rollback costs nothing.
				const size_t mark = out.size();
				out.append(buf + s, next - s);          // "<id>"
				out.append(buf + bs, bodyStart - bs);   // "{"
				size_t depth = 1, p = bodyStart, blockEnd = 0;
				bool hasOther = false, hadCloud = false, wellFormed = false;
				while (p < size)
				{
					const size_t ls = p, le = vdfLineEnd(buf, size, ls);
					const size_t ln = (le < size) ? le + 1 : size;
					if (vdfLineIsBrace(buf, ls, le, '{')) { ++depth; out.append(buf + ls, ln - ls); }
					else if (vdfLineIsBrace(buf, ls, le, '}'))
					{
						out.append(buf + ls, ln - ls);
						if (--depth == 0) { blockEnd = ln; wellFormed = true; break; }
					}
					else if (vdfLineIsCloudenabledKey(buf, ls, le)) hadCloud = true;   // drop this line
					else { hasOther = true; out.append(buf + ls, ln - ls); }
					p = ln;
				}
				if (wellFormed)
				{
					if (!hasOther) { out.resize(mark); changed = true; }   // cloudenabled-only/empty -> drop whole block
					else if (hadCloud) changed = true;                     // kept block, dropped its cloudenabled line(s)
					// else: block had no cloudenabled to drop -> re-emitted byte-for-byte, no change
					i = blockEnd;
					continue;
				}
				out.resize(mark);   // malformed (no matching brace) -> roll back, emit the id line verbatim below
			}
		}
		out.append(buf + s, next - s);
		i = next;
	}
	return changed;
}

// The FlushToDisk sharedconfig callsite (return address == callsite + 0x28). Used ONLY as an extra
// diagnostic signal — never as a hard gate (see hook): if this pattern shifts on a Steam update, the
// strip must keep working off the buffer content, not silently switch off.
static bool isSharedConfigWriteReturn(void* retAddr)
{
	if (Patterns::CConfigStore::SharedConfigWriteCallsite.address == LM_ADDRESS_BAD) return false;
	return reinterpret_cast<lm_address_t>(retAddr) == Patterns::CConfigStore::SharedConfigWriteCallsite.address + 0x28;
}

static uint32_t hkCConfigStore_WriteVdfFile(void* a0, uint32_t a1, uint32_t a2, void* a3, const char* buffer, uint32_t size)
{
	// Primary gate is the buffer CONTENT: only the roaming store's serialized buffer carries the
	// "UserRoamingConfigStore" root key, which version-robustly identifies the sharedconfig.vdf write.
	// We deliberately do NOT gate on the FlushToDisk callsite — a Steam update shifting that pattern
	// must not silently disable the strip (which would leak controlled apps to the cloud unnoticed).
	// Size cap: a real serialized roaming config is well under this. If a Steam-update ABI drift makes
	// (buffer,size) no longer describe this text buffer, an absurd `size` would make the content scan
	// below read far out of bounds (-> crash); above the cap we can't trust the args, so pass through.
	constexpr uint32_t kMaxRoamingConfigBytes = 64u * 1024u * 1024u;
	if (buffer && size && size <= kMaxRoamingConfigBytes)
	{
		const std::string_view sv(buffer, size);
		if (sv.find("\"UserRoamingConfigStore\"") != std::string_view::npos
			&& sv.find("\"cloudenabled\"") != std::string_view::npos)
		{
			// Callsite is only a cross-check: if it resolved but the return address doesn't match, the
			// roaming store is being written from an unexpected path — log once, but still filter.
			if (Patterns::CConfigStore::SharedConfigWriteCallsite.address != LM_ADDRESS_BAD
				&& !isSharedConfigWriteReturn(__builtin_return_address(0)))
			{
				g_pLog->once("Cloud-config strip: sharedconfig write from unexpected callsite; filtering on content\n");
			}

			try
			{
				static thread_local std::string stripped;
				if (stripControlledCloudFromBuffer(buffer, size, stripped))
				{
					g_pLog->debug("Cloud-config strip: filtered sharedconfig write buffer (%u -> %zu bytes)\n", size, stripped.size());
					return Hooks::CConfigStore_WriteVdfFile.tramp.fn(a0, a1, a2, a3, stripped.data(), static_cast<uint32_t>(stripped.size()));
				}
			}
			catch (...)
			{
				// fall through to the unfiltered write
			}
		}
	}

	return Hooks::CConfigStore_WriteVdfFile.tramp.fn(a0, a1, a2, a3, buffer, size);
}
static bool hkClientRemoteStorage_IsCloudEnabledForApp(void* pClientRemoteStorage, uint32_t appId)
{
	const bool enabled = Hooks::IClientRemoteStorage_IsCloudEnabledForApp.originalFn.fn(pClientRemoteStorage, appId);
	const bool disable = Apps::shouldDisableCloud(appId);
	g_pLog->once
	(
		"%s(%p, %u) -> %i\n",

		Hooks::IClientRemoteStorage_IsCloudEnabledForApp.name.c_str(),
		pClientRemoteStorage,
		appId,
		enabled
	);

	if (disable)
	{
		// ROOT-CAUSE fix for the lua-hot-reload "Steam Cloud out of date" badge. The badge only
		// appears after a hot-reload (markAndProcess re-stamps pkg0 -> AutoCloud re-evaluates every
		// app). That re-eval reads the per-app cloudenabled value from the config store's KeyValues
		// tree, so the value MUST be present in the store: SetCloudEnabledForApp(idx25)(false) writes
		// it (and the in-memory map), and the re-eval then sees the app as cloud-disabled -> no badge.
		// (Confirmed on device. Skipping the write, or intercepting the typed getter, both fail: the
		// value really has to live in the store's tree, which the eval tree-walks.) The unavoidable
		// downside is that the store flushes to the cloud-synced sharedconfig.vdf on save; that is
		// neutralised by the CConfigStore::WriteVdfFile detour which filters the serialized buffer
		// before Steam writes it.
		// Do it once per app, recursion-safe (SetCloudEnabledForApp re-enters this getter). Record the
		// appId in g_cloudWroteApps BEFORE the call so the flush strip knows this exact app's
		// cloudenabled is ours to remove (and never touches genuine user toggles).
		// Locate SetCloudEnabledForApp's slot by its build-stable funcHash (resolved + cached once).
		// If the funcHash can't be located, leave the in-memory cloud-disable OFF (badge fix then
		// rests on the WriteVdfFile strip alone) rather than calling a guessed slot, and don't record
		// the appId — we never wrote its cloudenabled. No hardcoded-index fallback.
		static const int setIdx = IpcOutbound::resolveIndex(IpcHash::IClientRemoteStorage::kSetCloudEnabledForApp_Name, IpcHash::IClientRemoteStorage::kSetCloudEnabledForApp);
		bool doSet = false;
		if (setIdx >= 0)
		{
			std::lock_guard<std::mutex> lk(g_cloudWroteMtx);
			doSet = g_cloudWroteApps.insert(appId).second;
		}
		if (doSet)
		{
			IpcOutbound::callAt<void(*)(void*, uint32_t, bool)>(setIdx, pClientRemoteStorage, appId, false);
			g_pLog->once("Cloud-disabled controlled app %u (SetCloudEnabledForApp=false) — suppresses post-hot-reload badge; persist stripped at flush\n", appId);
		}

		g_pLog->once("Disabled cloud for %u\n", appId);
		return false;
	}

	return enabled;
}

static bool g_bUpdateAppDownloadPlanReady = false;
static bool g_bConfigStoreWriteVdfFileReady = false;

static void hkClientRemoteStorage_RunIPCFrame(void* pClientRemoteStorage, void* a1, void* a2, void* a3)
{

	static bool hooked = false;
	if (!hooked)
	{
		std::shared_ptr<lm_vmt_t> vft = std::make_shared<lm_vmt_t>();
		LM_VmtNew(*reinterpret_cast<lm_address_t**>(pClientRemoteStorage), vft.get());

		// (The old vtable[idx25] slot-validity hardening is gone: SetCloudEnabledForApp's slot is now
		// located by funcHash at call time, which is itself the validity check — a miss skips the call.)
		installVFTByFuncHash(Hooks::IClientRemoteStorage_IsCloudEnabledForApp, vft, IpcHash::IClientRemoteStorage::kIsCloudEnabledForApp_Name, IpcHash::IClientRemoteStorage::kIsCloudEnabledForApp, hkClientRemoteStorage_IsCloudEnabledForApp);

		g_pLog->debug("IClientRemoteStorage->vft at %p\n", vft->vtable);

		hooked = true;
	}
	
	//Cloud & Workshop
	FakeAppIds::runIPCFrame(false);
	Hooks::IClientRemoteStorage_RunIPCFrame.tramp.fn(pClientRemoteStorage, a1, a2, a3);
	FakeAppIds::runIPCFrame(true);
}

static void hkClientUGC_RunIPCFrame(void* pClientUGC, void* a1, void* a2, void* a3)
{
	//Workshop
	FakeAppIds::runIPCFrame(false);
	Hooks::IClientUGC_RunIPCFrame.tramp.fn(pClientUGC, a1, a2, a3);
	FakeAppIds::runIPCFrame(true);
}

static uint32_t hkClientUtils_GetAppId(void* pClientUtils)
{
	uint32_t appId = Hooks::IClientUtils_GetAppId.originalFn.fn(pClientUtils);

	g_pLog->debug
	(
		"%s(%p) -> %u\n",

		Hooks::IClientUtils_GetAppId.name.c_str(),
		pClientUtils,
		appId
	);

	const uint32_t real = FakeAppIds::getRealAppIdForCurrentPipe(false);
	if(real)
	{
		g_pLog->debug("Overwriting appId with %u\n", real);
		return real;
	}

	return appId;
}

static bool hkClientUtils_GetOfflineMode(void* pClientUtils)
{
	const bool ret = Hooks::IClientUtils_GetOfflineMode.originalFn.fn(pClientUtils);

	if (Misc::shouldFakeOffline())
	{
		return true;
	}

	return ret;
}

static void hkClientUtils_RunIPCFrame(void* pClientUtils, void* a1, void* a2, void* a3)
{
	static std::atomic_bool hooked {false};
	static std::mutex hookMtx;
	if (!hooked.load(std::memory_order_acquire))
	{
		std::lock_guard<std::mutex> lock(hookMtx);
		if (!hooked.load(std::memory_order_relaxed))
		{
			g_pLog->debug
			(
				"%s first entry: pClientUtils=%p a1=%p a2=%p a3=%p tramp=%p original=%p size=%zu\n",

				Hooks::IClientUtils_RunIPCFrame.name.c_str(),
				pClientUtils,
				a1,
				a2,
				a3,
				Hooks::IClientUtils_RunIPCFrame.tramp.address,
				Hooks::IClientUtils_RunIPCFrame.originalFn.address,
				Hooks::IClientUtils_RunIPCFrame.size
			);

			g_pClientUtils = reinterpret_cast<IClientUtils*>(pClientUtils);

			std::shared_ptr<lm_vmt_t> vft = std::make_shared<lm_vmt_t>();
			LM_VmtNew(*reinterpret_cast<lm_address_t**>(pClientUtils), vft.get());

			installVFTByFuncHash(Hooks::IClientUtils_GetAppId,       vft, IpcHash::IClientUtils::kGetAppId_Name,      IpcHash::IClientUtils::kGetAppId,      hkClientUtils_GetAppId);
			installVFTByFuncHash(Hooks::IClientUtils_GetOfflineMode, vft, IpcHash::IClientUtils::kGetOfflineMode_Name, IpcHash::IClientUtils::kGetOfflineMode, hkClientUtils_GetOfflineMode);

			g_pLog->debug("IClientUtils->vft at %p\n", vft->vtable);

			// IClientUtils_RunIPCFrame is only needed as a one-shot seam to install the
			// VFT hooks above. Remove the detour after that so Steam threads do not keep
			// tail-calling through our trampoline fast path during startup/shutdown.
			g_pLog->debug
			(
				"%s removing one-shot detour after VFT hook: tramp=%p original=%p size=%zu\n",

				Hooks::IClientUtils_RunIPCFrame.name.c_str(),
				Hooks::IClientUtils_RunIPCFrame.tramp.address,
				Hooks::IClientUtils_RunIPCFrame.originalFn.address,
				Hooks::IClientUtils_RunIPCFrame.size
			);
			Hooks::IClientUtils_RunIPCFrame.remove();
			hooked.store(true, std::memory_order_release);
		}
	}

	Hooks::IClientUtils_RunIPCFrame.originalFn.fn(pClientUtils, a1, a2, a3);
}

static bool hkClientUser_BLoggedOn(void* pClientUser)
{
	const bool ret = Hooks::IClientUser_BLoggedOn.tramp.fn(pClientUser);
	//Useless logging
	//g_pLog->debug
	//(
	//	"%s(%p) -> %i\n",
	//	Hooks::IClientUser_BLoggedOn.name.c_str(),
	//	pClientUser,
	//	ret
	//);
	
	if (Misc::shouldFakeOffline())
	{
		return false;
	}

	return ret;
}

static uint32_t hkClientUser_BUpdateOwnershipTicket(void* pClientUser, uint32_t appId, bool staleOnly)
{
	auto cached = Ticket::getCachedTicket(appId);
	const bool spoofedOwnership = Ownership::shouldSpoofOwnership(appId);
	g_pLog->debug
	(
		"%s enter: pClientUser=%p appId=%u staleOnly=%i spoofed=%i cachedSteamId=%u cachedTicketSize=%zu steamEngine=%p\n",

		Hooks::IClientUser_BUpdateAppOwnershipTicket.name.c_str(),
		pClientUser,
		appId,
		staleOnly,
		spoofedOwnership,
		cached.steamId,
		cached.ticket.size(),
		g_pSteamEngine
	);

	if (spoofedOwnership)
	{
		auto* user = g_pSteamEngine ? g_pSteamEngine->getUser(0) : nullptr;
		g_pLog->debug
		(
			"%s suppressing remote update: appId=%u user=%p localTicketSize=%zu\n",

			Hooks::IClientUser_BUpdateAppOwnershipTicket.name.c_str(),
			appId,
			user,
			cached.ticket.size()
		);

		if (user && !cached.ticket.empty())
		{
			user->updateAppOwnershipTicket(appId, reinterpret_cast<void*>(cached.ticket.data()), cached.ticket.size());
			g_pLog->once("Suppressed remote AppOwnershipTicket update for %u; loaded local ticket (%zu bytes)\n", appId, cached.ticket.size());
			return 1;
		}

		if (!user)
		{
			g_pLog->warn("Suppressed remote AppOwnershipTicket update for %u but CUser is unavailable\n", appId);
		}
		else
		{
			g_pLog->debug("Suppressed remote AppOwnershipTicket update for %u without local ticket; not posting synthetic OK callback\n", appId);
		}

		g_pLog->once("Suppressed remote AppOwnershipTicket update for %u without local ticket\n", appId);
		return 1;
	}

	if (Apps::isGenuinelySubscribed(appId) && !cached.steamId)
	{
		staleOnly = false;
		g_pLog->debug("Force re-requesting OwnershipInfo for %u\n", appId);
	}

	const uint32_t ret = Hooks::IClientUser_BUpdateAppOwnershipTicket.tramp.fn(pClientUser, appId, staleOnly);

	g_pLog->debug
	(
		"%s(%p, %u, %i) -> %u\n",

		Hooks::IClientUser_BUpdateAppOwnershipTicket.name.c_str(),
		pClientUser,
		appId,
		staleOnly,
		ret
	);

	return ret;
}


static uint8_t hkClientUser_IsUserSubscribedAppInTicket(void* pClientUser, uint32_t steamId, uint32_t a2, uint32_t a3, uint32_t appId)
{
	const uint8_t ticketState = Hooks::IClientUser_IsUserSubscribedAppInTicket.tramp.fn(pClientUser, steamId, a2, a3, appId);
	//g_pLog->once("IClientUser::IsUserSubscribedAppInTicket(%p, %u, %u, %u, %u) -> %i\n", pClientUser, steamId, a2, a3, appId, ticketState);
	//Don't log the steamId, protect users from themselves and stuff
	g_pLog->once
	(
		"%s(%p, %u, %u, %u) -> %i\n",

		Hooks::IClientUser_IsUserSubscribedAppInTicket.name.c_str(),
		pClientUser,
		a2,
		a3,
		appId,
		ticketState
	);
	
	if (DLC::userSubscribedInTicket(appId))
	{
		//Owned and subscribed hehe :)
		return 0;
	}

	return ticketState;
}

__attribute__((stdcall))
static uint32_t hkClientUser_GetSteamId(uint32_t steamId)
{
	if (!g_currentSteamId)
	{
		g_currentSteamId = steamId;
	}

	Ticket::SavedTicket ticket = Ticket::getCachedEncryptedTicket(FakeAppIds::getRealAppIdForCurrentPipe());

	if (ticket.steamId)
	{
		steamId = ticket.steamId;
	}
	else
	{
		//One time spoof should be enough for this type. Atomic read-and-clear so
		//a concurrent GetSteamId/GetAppOwnershipTicketExtendedData on another
		//thread cannot tear or lose the value.
		const uint32_t spoof = Ticket::oneTimeSteamIdSpoof.exchange(0);
		if (spoof)
		{
			steamId = spoof;
		}
	}

	return steamId;
}

static bool hkClientUser_RequiresLegacyCDKey(void* pClientUser, uint32_t appId, uint32_t* a2)
{
	const bool requiresKey = Hooks::IClientUser_RequiresLegacyCDKey.tramp.fn(pClientUser, appId, a2);
	g_pLog->once
	(
		"%s(%p, %u, %u) -> %i\n",

		Hooks::IClientUser_RequiresLegacyCDKey.name.c_str(),
		pClientUser,
		appId,
		a2,
		requiresKey
	);

	if (Apps::shouldDisableCDKey(appId))
	{
		g_pLog->once("Disable CD Key for %u\n", appId);
		return false;
	}

	return requiresKey;
}

// IPC post-handler: GetAppOwnershipTicketExtendedData
// Response layout (RE-verified):
//   0x00: returnValue (u32)
//   0x04: pTicket (ticketSize bytes)
//   0x04+ticketSize: piAppId (u32)
//   0x08+ticketSize: piSteamId (u32)
//   0x0c+ticketSize: piSignature (u32)
//   0x10+ticketSize: pcbSignature (u32)
static void hIpc_User_GetAppOwnershipTicketExtendedData(IpcDispatch::IpcCallCtx& ctx)
{
	const uint8_t* pkt = IpcDispatch::requestPtr(ctx.pRead);
	if (!pkt)
	{
		ctx.original(ctx.pInterface, ctx.pRead, ctx.pWrite, ctx.a3);
		return;
	}

	const uint32_t appId     = IpcDispatch::readArgU32(pkt, 0);
	const uint32_t ticketSize = IpcDispatch::readArgU32(pkt, 4);

	if (!Ownership::shouldSpoofOwnership(appId))
	{
		ctx.original(ctx.pInterface, ctx.pRead, ctx.pWrite, ctx.a3);
		Ticket::getTicketOwnershipExtendedData(appId);
		return;
	}

	ForgeTicket::acquireSourceTicket(ctx.pInterface);

	ForgeTicket::AppOwnershipTicket ticket{};
	if (!ForgeTicket::getAppOwnershipTicket(appId, ticket))
	{
		ctx.original(ctx.pInterface, ctx.pRead, ctx.pWrite, ctx.a3);
		return;
	}

	// Run original to allocate the response buffer
	ctx.original(ctx.pInterface, ctx.pRead, ctx.pWrite, ctx.a3);

	uint8_t* resp = IpcDispatch::responsePtr(ctx.pWrite);
	const uint32_t respLen = IpcDispatch::responseLen(ctx.pWrite);
	const uint32_t needed = 0x14 + ticketSize;
	if (!resp || respLen < needed)
	{
		g_pLog->warn("ForgeTicket: response buffer too small (%u < %u) for appid %u\n",
			respLen, needed, appId);
		return;
	}

	if (ticket.data.size() > ticketSize)
	{
		g_pLog->warn("ForgeTicket: ticket too large (%zu > %u) for appid %u\n",
			ticket.data.size(), ticketSize, appId);
		return;
	}

	IpcDispatch::writeU32(resp, 0x00, ticket.totalSize);
	std::memcpy(resp + 0x04, ticket.data.data(), ticket.data.size());
	IpcDispatch::writeU32(resp, 0x04 + ticketSize, ticket.appIdOffset);
	IpcDispatch::writeU32(resp, 0x08 + ticketSize, ticket.steamIdOffset);
	IpcDispatch::writeU32(resp, 0x0c + ticketSize, ticket.signatureOffset);
	IpcDispatch::writeU32(resp, 0x10 + ticketSize, ticket.signatureSize);

	// SteamID linkage: extract from ticket data at offset 8 (uint64 LE, low 32 bits)
	if (ticket.data.size() >= 16)
	{
		uint64_t sid64 = 0;
		std::memcpy(&sid64, ticket.data.data() + ForgeTicket::kAppTicketSteamIdOffset, sizeof(uint64_t));
		Ticket::oneTimeSteamIdSpoof = static_cast<uint32_t>(sid64 & 0xFFFFFFFFULL);
	}

	g_pLog->info("ForgeTicket: injected ticket for appid %u (totalSize=%u, forged=%s)\n",
		appId, ticket.totalSize,
		ticket.data.size() != ticket.totalSize ? "yes" : "no");
}

static void hkClientUser_RunIPCFrame(void* pClientUser, void* a1, void* a2, void* a3)
{
	IpcDispatch::dispatch(pClientUser, a1, a2, a3,
		[](void* i, void* x, void* y, void* z){ Hooks::IClientUser_RunIPCFrame.tramp.fn(i, x, y, z); });
}

static void hkClientUserStats_RunIPCFrame(void* pClientUserStats, void* a1, void* a2, void* a3)
{
	//Achievements
	FakeAppIds::runIPCFrame(false);
	Hooks::IClientUserStats_RunIPCFrame.tramp.fn(pClientUserStats, a1, a2, a3);
	FakeAppIds::runIPCFrame(true);
}

static void hkSteamMatchmakingPingResponse_ServerResponded(void* pSteamMatchingPingResponse, gameserverdetails_t* details)
{
	FakeAppIds::pingResponse(details);
	Hooks::ISteamMatchmakingPingResponse_ServerResponded.tramp.fn(pSteamMatchingPingResponse, details);
}

static void patchRetn(lm_address_t address)
{
	constexpr lm_byte_t retn = 0xC3;

	lm_prot_t oldProt;
	LM_ProtMemory(address, 1, LM_PROT_XRW, &oldProt); //LM_PROT_W Should be enough, but just in case something tries to execute it inbetween us setting the prot and writing to it
	LM_WriteMemory(address, &retn, 1);
	LM_ProtMemory(address, 1, oldProt, LM_NULL);
}

static lm_address_t hkNakedGetSteamId;
static bool createAndPlaceSteamIdHook()
{
	hkNakedGetSteamId = LM_AllocMemory(0, LM_PROT_XRW);
	if (hkNakedGetSteamId == LM_ADDRESS_BAD)
	{
		g_pLog->debug("Failed to allocate memory for GetSteamId!\n");
		return false;
	}

	g_pLog->debug("Allocated memory for GetSteamId hook at %p\n", hkNakedGetSteamId);

	auto insts = std::vector<lm_inst_t>();
	lm_address_t readAddr = Hooks::IClientUser_GetSteamId;
	for(;;)
	{
		lm_inst_t inst;
		if (!LM_Disassemble(readAddr, &inst))
		{
			g_pLog->debug("Failed to disassemble function at %p!\n", readAddr);
			return false;
		}

		insts.emplace_back(inst);
		readAddr = inst.address + inst.size;

		if (strcmp(inst.mnemonic, "ret") == 0)
		{
			break;
		}
	}

	const unsigned int retIdx = insts.size() - 1;

	g_pLog->debug("Ret is instruction number %u\n", retIdx);
	//TODO: Create InlineHook class for this
	size_t totalBytes = 0;
	unsigned int instsToOverwrite = 0;
	for(int i = retIdx; i >= 0; i--)
	{
		lm_inst_t inst = insts.at(i);
		totalBytes += inst.size;
		instsToOverwrite++;

		//Need only 5 bytes to place relative jmp
		if (totalBytes >= 5)
		{
			break;
		}
	}

	static uint32_t steamId;

	lm_address_t writeAddr = hkNakedGetSteamId;
	//I really didn't want to use pushad and popad since it's just lazy
	//But I'm bad at this so this has to do
	MemHlp::assembleCodeAt(writeAddr, "mov [%p], ecx", &steamId);
	MemHlp::assembleCodeAt(writeAddr, "pushad", nullptr);
	MemHlp::assembleCodeAt(writeAddr, "pushfd", nullptr);
	//MemHlp::assembleCodeAt(writeAddr, "pushfq", nullptr);

	MemHlp::assembleCodeAt(writeAddr, "mov eax, %p", &hkClientUser_GetSteamId);
	MemHlp::assembleCodeAt(writeAddr, "mov ebx, [%p]", &steamId);
	MemHlp::assembleCodeAt(writeAddr, "push ebx", steamId);
	MemHlp::assembleCodeAt(writeAddr, "call eax", nullptr);
	MemHlp::assembleCodeAt(writeAddr, "mov [%p], eax", &steamId);

	//MemHlp::assembleCodeAt(writeAddr, "popfq", nullptr);
	MemHlp::assembleCodeAt(writeAddr, "popfd", nullptr);
	MemHlp::assembleCodeAt(writeAddr, "popad", nullptr);
	MemHlp::assembleCodeAt(writeAddr, "mov ecx, [%p]", &steamId);
	
	//TODO: Dynamically resolve register which holds SteamId
	//MemHlp::assembleCodeAt(writeAddr, "mov [%p], ecx", &g_currentSteamId);

	//MemHlp::assembleCodeAt(writeAddr, "push eax", nullptr);

	//MemHlp::assembleCodeAt(writeAddr, "mov eax, [%p]", &Ticket::steamIdSpoof);
	//MemHlp::assembleCodeAt(writeAddr, "test eax, eax", nullptr);
	//MemHlp::assembleCodeAt(writeAddr, "je %p", 4); //2 bytes
	//MemHlp::assembleCodeAt(writeAddr, "mov ecx, eax", nullptr); //2 bytes
	//MemHlp::assembleCodeAt(writeAddr, "mov eax, 0", nullptr); //5 bytes
	//MemHlp::assembleCodeAt(writeAddr, "mov [%p], eax", &Ticket::steamIdSpoof); //5 bytes
	//
	//MemHlp::assembleCodeAt(writeAddr, "pop eax", nullptr);

	//Write the overwritten instructions after our hook code
	for (unsigned int i = 0; i < instsToOverwrite; i++)
	{
		lm_inst_t inst = insts.at(insts.size() - instsToOverwrite + i);
		memcpy(reinterpret_cast<void*>(writeAddr), inst.bytes, inst.size);

		writeAddr += inst.size;
		g_pLog->debug("Copied %s %s to tramp\n", inst.mnemonic, inst.op_str);
	}

	lm_address_t jmpAddr = insts.at(insts.size() - instsToOverwrite).address;
	g_pLog->debug("Placing jmp at %p\n", jmpAddr);

	//Might be worth to convert to LM_AssembleEx, but whatever
	lm_prot_t oldProt;
	LM_ProtMemory(jmpAddr, 5, LM_PROT_XRW, &oldProt);
	*reinterpret_cast<lm_byte_t*>(jmpAddr) = 0xE9;
	*reinterpret_cast<lm_address_t*>(jmpAddr + 1) = hkNakedGetSteamId - jmpAddr - 5;
	LM_ProtMemory(jmpAddr, 5, oldProt, nullptr);

	return true;
}

namespace Hooks
{
	//TODO: Lazily intialize in a different way, or preload glibc
	DetourHook<TraceIPC_t> TraceIPC;

	DetourHook<IClientAppManager_RunIPCFrame_t> IClientAppManager_RunIPCFrame;
	DetourHook<IClientApps_RunIPCFrame_t> IClientApps_RunIPCFrame;
	DetourHook<IClientRemoteStorage_RunIPCFrame_t> IClientRemoteStorage_RunIPCFrame;
	DetourHook<IClientUGC_RunIPCFrame_t> IClientUGC_RunIPCFrame;
	DetourHook<IClientUtils_RunIPCFrame_t> IClientUtils_RunIPCFrame;
	DetourHook<IClientUser_RunIPCFrame_t> IClientUser_RunIPCFrame;
	DetourHook<IClientUserStats_RunIPCFrame_t> IClientUserStats_RunIPCFrame;

	DetourHook<LoadDepotDecryptionKey_t> LoadDepotDecryptionKey;
	DetourHook<BuildDepotDependency_t> BuildDepotDependency;
	DetourHook<BUpdateAppDownloadPlan_t> BUpdateAppDownloadPlan;

	DetourHook<CAPIJob_GetPlayerStats_t> CAPIJob_GetPlayerStats;

	DetourHook<CProtoBufMsgBase_InitFromPacket_t> CProtoBufMsgBase_InitFromPacket;
	DetourHook<CProtoBufMsgBase_Send_t> CProtoBufMsgBase_Send;

	DetourHook<CWebSocketConnection_BBuildAndAsyncSendFrame_t> CWebSocketConnection_BBuildAndAsyncSendFrame;
	DetourHook<CCMConnection_RecvPkt_t> CCMConnection_RecvPkt;

	DetourHook<CSteamMatchmakingServers_GetServerDetails_t> CSteamMatchmakingServers_GetServerDetails;
	DetourHook<CSteamMatchmakingServers_RequestInternetServerList_t> CSteamMatchmakingServers_RequestInternetServerList;

	DetourHook<CSteamEngine_Init_t> CSteamEngine_Init;
	DetourHook<CSteamEngine_SetAppIdForCurrentPipe_t> CSteamEngine_SetAppIdForCurrentPipe;

	DetourHook<CUser_CheckAppOwnership_t> CUser_CheckAppOwnership;
	DetourHook<CUser_GetSubscribedApps_t> CUser_GetSubscribedApps;

	MarkLicenseAsChanged_t         oMarkLicenseAsChanged         = nullptr;
	ProcessPendingLicenseUpdates_t oProcessPendingLicenseUpdates = nullptr;
	CUtlMemory_Grow_t              oCUtlMemoryGrow               = nullptr;
	DetourHook<CPackageInfo_GetPackageInfo_t> CPackageInfo_GetPackageInfo;
	DetourHook<CConfigStore_WriteVdfFile_t> CConfigStore_WriteVdfFile;

	DetourHook<CSteamUI_GetAppByID_detour_t>          CSteamUIAppController_GetAppByID;
	DetourHook<CUpdateManager_MarkAppChange_detour_t> CUpdateManager_MarkAppChange;
	DetourHook<CSteamUI_FillInAppOverview_t>          CSteamUIAppController_FillInAppOverview;

	DetourHook<IClientAppManager_BCanRemotePlayTogether_t> IClientAppManager_BCanRemotePlayTogether;

	DetourHook<IClientUser_BLoggedOn_t> IClientUser_BLoggedOn;
	DetourHook<IClientUser_BUpdateAppOwnershipTicket_t> IClientUser_BUpdateAppOwnershipTicket;
	DetourHook<IClientUser_IsUserSubscribedAppInTicket_t> IClientUser_IsUserSubscribedAppInTicket;
	DetourHook<IClientUser_RequiresLegacyCDKey_t> IClientUser_RequiresLegacyCDKey;

	VFTHook<IClientAppManager_BIsDlcEnabled_t> IClientAppManager_BIsDlcEnabled("IClientAppManager::BIsDlcEnabled");
	VFTHook<IClientAppManager_GetAppUpdateInfo_t> IClientAppManager_GetAppUpdateInfo("IClientAppManager::GetAppUpdateInfo");
	VFTHook<IClientAppManager_LaunchApp_t> IClientAppManager_LaunchApp("IClientAppManager::LaunchApp");
	VFTHook<IClientAppManager_IsAppDlcInstalled_t> IClientAppManager_IsAppDlcInstalled("IClientAppManager::IsAppDlcInstalled");

	VFTHook<IClientApps_GetDLCDataByIndex_t> IClientApps_GetDLCDataByIndex("IClientApps::GetDLCDataByIndex");
	VFTHook<IClientApps_GetDLCCount_t> IClientApps_GetDLCCount("IClientApps::GetDLCCount");

	VFTHook<IClientRemoteStorage_IsCloudEnabledForApp_t> IClientRemoteStorage_IsCloudEnabledForApp("IClientRemoteStorage::IsCloudEnabledForApp");

	VFTHook<IClientUtils_GetAppId_t> IClientUtils_GetAppId("IClientUtils::GetAppId");
	VFTHook<IClientUtils_GetOfflineMode_t> IClientUtils_GetOfflineMode("IClientUtils::GetOfflineMode");


	//steamui.so
	DetourHook<ISteamMatchmakingPingResponse_ServerResponded_t> ISteamMatchmakingPingResponse_ServerResponded;


	//Naked
	lm_address_t IClientUser_GetSteamId;
}

bool Hooks::setup()
{
	g_pLog->debug("Hooks::setup()\n");

	IClientUser_GetSteamId = Patterns::IClientUser::GetSteamId.address;

	oMarkLicenseAsChanged         = reinterpret_cast<MarkLicenseAsChanged_t>(Patterns::CUser::MarkLicenseAsChanged.address);
	oProcessPendingLicenseUpdates = reinterpret_cast<ProcessPendingLicenseUpdates_t>(Patterns::CUser::ProcessPendingLicenseUpdates.address);
	oCUtlMemoryGrow               = reinterpret_cast<CUtlMemory_Grow_t>(Patterns::CUtlMemory::Grow.address);

	g_bConfigStoreWriteVdfFileReady = CConfigStore_WriteVdfFile.setup(Patterns::CConfigStore::WriteVdfFile, &hkCConfigStore_WriteVdfFile);
	g_pLog->debug
	(
		"CConfigStore::WriteVdfFile hook: ready=%i callsite=%p\n",
		g_bConfigStoreWriteVdfFileReady,
		Patterns::CConfigStore::SharedConfigWriteCallsite.address
	);
	// Make a pattern miss loud: without WriteVdfFile the cloud-config strip is OFF and controlled apps
	// would silently persist/sync. (The callsite is only a diagnostic now, so its miss is non-fatal.)
	if (!g_bConfigStoreWriteVdfFileReady)
	{
		g_pLog->warn("Cloud-config strip DISABLED: CConfigStore::WriteVdfFile pattern did not resolve — controlled apps' cloudenabled may persist to the cloud. Re-derive the pattern.\n");
	}
	else if (Patterns::CConfigStore::SharedConfigWriteCallsite.address == LM_ADDRESS_BAD)
	{
		g_pLog->info("Cloud-config strip: SharedConfigWriteCallsite pattern unresolved; filtering on buffer content only (still active).\n");
	}

	bool succeeded =
		TraceIPC.setup(Patterns::TraceIPC, &hkTraceIPC)

		&& LoadDepotDecryptionKey.setup(Patterns::LoadDepotDecryptionKey, &hkLoadDepotDecryptionKey)
		&& BuildDepotDependency.setup(Patterns::BuildDepotDependency, &hkBuildDepotDependency)

		&& CAPIJob_GetPlayerStats.setup(Patterns::CAPIJob::GetPlayerStats, &hkCAPIJob_GetPlayerStats)

		&& CProtoBufMsgBase_InitFromPacket.setup(Patterns::CProtoBufMsgBase::InitFromPacket, &hkProtoBufMsgBase_InitFromPacket)
		&& CProtoBufMsgBase_Send.setup(Patterns::CProtoBufMsgBase::Send, &hkProtoBufMsgBase_Send)
		&& CWebSocketConnection_BBuildAndAsyncSendFrame.setup(Patterns::CWebSocketConnection::BBuildAndAsyncSendFrame, &hkCWebSocketConnection_BBuildAndAsyncSendFrame)
		&& CCMConnection_RecvPkt.setup(Patterns::CCMConnection::RecvPkt, &hkCCMConnection_RecvPkt)

		&& CSteamMatchmakingServers_GetServerDetails.setup(Patterns::CSteamMatchmakingServers::GetServerDetails, &hkSteamMatchmakingServers_GetServerDetails)
		&& CSteamMatchmakingServers_RequestInternetServerList.setup(Patterns::CSteamMatchmakingServers::RequestInternetServerList, &hkSteamMatchmakingServers_RequestInternetServerList)

		&& CUser_CheckAppOwnership.setup(Patterns::CUser::CheckAppOwnership, &hkUser_CheckAppOwnership)
		&& CUser_GetSubscribedApps.setup(Patterns::CUser::GetSubscribedApps, &hkUser_GetSubscribedApps)

		&& CPackageInfo_GetPackageInfo.setup(Patterns::CPackageInfo::GetPackageInfo, &hkCPackageInfo_GetPackageInfo)

		&& CSteamUIAppController_GetAppByID.setup(Patterns::CSteamUIAppController::GetAppByID, &hkCSteamUI_GetAppByID)
		&& CUpdateManager_MarkAppChange.setup(Patterns::CUpdateManager::MarkAppChange, &hkCUpdateManager_MarkAppChange)
		&& CSteamUIAppController_FillInAppOverview.setup(Patterns::CSteamUIAppController::FillInAppOverview, &hkCSteamUI_FillInAppOverview)

		&& CSteamEngine_Init.setup(Patterns::CSteamEngine::Init, &hkSteamEngine_Init)
		&& CSteamEngine_SetAppIdForCurrentPipe.setup(Patterns::CSteamEngine::SetAppIdForCurrentPipe, &hkSteamEngine_SetAppIdForCurrentPipe)

		&& IClientAppManager_BCanRemotePlayTogether.setup(Patterns::IClientAppManager::BCanRemotePlayTogether, hkClientAppManager_BCanRemotePlayTogether)

		&& IClientApps_RunIPCFrame.setup(Patterns::IClientApps::RunIPCFrame, hkClientApps_RunIPCFrame)
		&& IClientAppManager_RunIPCFrame.setup(Patterns::IClientAppManager::RunIPCFrame, hkClientAppManager_RunIPCFrame)
		&& IClientRemoteStorage_RunIPCFrame.setup(Patterns::IClientRemoteStorage::RunIPCFrame, hkClientRemoteStorage_RunIPCFrame)
		&& IClientUGC_RunIPCFrame.setup(Patterns::IClientUGC::RunIPCFrame, hkClientUGC_RunIPCFrame)
		&& IClientUtils_RunIPCFrame.setup(Patterns::IClientUtils::RunIPCFrame, hkClientUtils_RunIPCFrame);

	IpcDispatch::registerHandler(
		IpcHash::IClientUser::kGetAppOwnershipTicketExtendedData,
		hIpc_User_GetAppOwnershipTicketExtendedData);

	succeeded = succeeded
		&& IClientUser_RunIPCFrame.setup(Patterns::IClientUser::RunIPCFrame, hkClientUser_RunIPCFrame)
		&& IClientUserStats_RunIPCFrame.setup(Patterns::IClientUserStats::RunIPCFrame, hkClientUserStats_RunIPCFrame)

		&& IClientUser_BLoggedOn.setup(Patterns::IClientUser::BLoggedOn, &hkClientUser_BLoggedOn)
		&& IClientUser_BUpdateAppOwnershipTicket.setup(Patterns::IClientUser::BUpdateAppOwnershipTicket, hkClientUser_BUpdateOwnershipTicket)
		&& IClientUser_IsUserSubscribedAppInTicket.setup(Patterns::IClientUser::IsUserSubscribedAppInTicket, &hkClientUser_IsUserSubscribedAppInTicket)
		&& IClientUser_RequiresLegacyCDKey.setup(Patterns::IClientUser::RequiresLegacyCDKey, hkClientUser_RequiresLegacyCDKey)

		&& ISteamMatchmakingPingResponse_ServerResponded.setup(Patterns::ISteamMatchmakingPingResponse::ServerResponded, hkSteamMatchmakingPingResponse_ServerResponded);

	g_bUpdateAppDownloadPlanReady = BUpdateAppDownloadPlan.setup(Patterns::BUpdateAppDownloadPlan, &hkBUpdateAppDownloadPlan);

	g_pLog->debug
	(
		"BUpdateAppDownloadPlan hook: ready=%i\n",
		g_bUpdateAppDownloadPlanReady
	);

	LuaLoader::setOnDepotsChanged(&Package::notifyLicenseChanged);

	if (!succeeded)
	{
		return false;
	}

	Hooks::place();
	//This is unnecessary but I'll keep this for now in case I wanna improve error checks
	return succeeded;
}

void Hooks::place()
{
	if (g_config.disableFamilyLock.get())
	{
		patchRetn(Patterns::FamilyGroupRunningApp.address);
		patchRetn(Patterns::StopPlayingBorrowedApp.address);
	}

	//Detours
	TraceIPC.place();

	LoadDepotDecryptionKey.place();
	BuildDepotDependency.place();
	if (g_bUpdateAppDownloadPlanReady)
	{
		BUpdateAppDownloadPlan.place();
	}
	if (g_bConfigStoreWriteVdfFileReady)
	{
		CConfigStore_WriteVdfFile.place();
	}

	CAPIJob_GetPlayerStats.place();

	CProtoBufMsgBase_InitFromPacket.place();
	CProtoBufMsgBase_Send.place();
	CWebSocketConnection_BBuildAndAsyncSendFrame.place();
	CCMConnection_RecvPkt.place();

	CSteamEngine_Init.place();
	CSteamEngine_SetAppIdForCurrentPipe.place();

	CSteamMatchmakingServers_GetServerDetails.place();
	CSteamMatchmakingServers_RequestInternetServerList.place();

	CUser_CheckAppOwnership.place();
	CUser_GetSubscribedApps.place();
	CPackageInfo_GetPackageInfo.place();

	CSteamUIAppController_GetAppByID.place();
	CUpdateManager_MarkAppChange.place();
	CSteamUIAppController_FillInAppOverview.place();

	IClientAppManager_BCanRemotePlayTogether.place();

	IClientApps_RunIPCFrame.place();
	IClientAppManager_RunIPCFrame.place();
	IClientRemoteStorage_RunIPCFrame.place();
	IClientUGC_RunIPCFrame.place();
	IClientUtils_RunIPCFrame.place();
	IClientUser_RunIPCFrame.place();
	IClientUserStats_RunIPCFrame.place();

	IClientUser_BLoggedOn.place();
	IClientUser_BUpdateAppOwnershipTicket.place();
	IClientUser_IsUserSubscribedAppInTicket.place();
	IClientUser_RequiresLegacyCDKey.place();

	ISteamMatchmakingPingResponse_ServerResponded.place();

	createAndPlaceSteamIdHook();
}

void Hooks::remove()
{
	//Detours
	TraceIPC.remove();

	LoadDepotDecryptionKey.remove();
	BuildDepotDependency.remove();
	if (g_bUpdateAppDownloadPlanReady)
	{
		BUpdateAppDownloadPlan.remove();
	}
	if (g_bConfigStoreWriteVdfFileReady)
	{
		CConfigStore_WriteVdfFile.remove();
	}

	CAPIJob_GetPlayerStats.remove();

	CProtoBufMsgBase_InitFromPacket.remove();
	CProtoBufMsgBase_Send.remove();
	CWebSocketConnection_BBuildAndAsyncSendFrame.remove();
	CCMConnection_RecvPkt.remove();

	CSteamEngine_Init.remove();
	CSteamEngine_SetAppIdForCurrentPipe.remove();

	CSteamMatchmakingServers_GetServerDetails.remove();
	CSteamMatchmakingServers_RequestInternetServerList.remove();

	CUser_CheckAppOwnership.remove();
	CUser_GetSubscribedApps.remove();
	CPackageInfo_GetPackageInfo.remove();

	CSteamUIAppController_GetAppByID.remove();
	CUpdateManager_MarkAppChange.remove();
	CSteamUIAppController_FillInAppOverview.remove();

	IClientAppManager_BCanRemotePlayTogether.remove();

	IClientApps_RunIPCFrame.remove();
	IClientAppManager_RunIPCFrame.remove();
	IClientRemoteStorage_RunIPCFrame.remove();
	IClientUGC_RunIPCFrame.remove();
	IClientUtils_RunIPCFrame.remove();
	IClientUser_RunIPCFrame.remove();
	IClientUserStats_RunIPCFrame.remove();

	IClientUser_BLoggedOn.remove();
	IClientUser_BUpdateAppOwnershipTicket.remove();
	IClientUser_IsUserSubscribedAppInTicket.remove();
	IClientUser_RequiresLegacyCDKey.remove();

	ISteamMatchmakingPingResponse_ServerResponded.remove();

	//VFT Hooks
	IClientAppManager_BIsDlcEnabled.remove();
	IClientAppManager_GetAppUpdateInfo.remove();
	IClientAppManager_LaunchApp.remove();
	IClientAppManager_IsAppDlcInstalled.remove();

	IClientApps_GetDLCDataByIndex.remove();
	IClientApps_GetDLCCount.remove();

	IClientRemoteStorage_IsCloudEnabledForApp.remove();

	IClientUtils_GetAppId.remove();
	
	//TODO: Remove jmp
	if (hkNakedGetSteamId != LM_ADDRESS_BAD)
	{
		LM_FreeMemory(hkNakedGetSteamId, 0);
	}
}
