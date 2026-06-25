#pragma once

#include "libmem/libmem.h"

#include <cstddef>
#include <memory>
#include <string>

class CAppOwnershipInfo;
class CProtoBufMsgBase;

struct gameserverdetails_t;
struct CNetPacket;

struct Pattern_t;

template<typename T>
union FunctionUnion_t
{
	T fn;
	lm_address_t address;
};

//TODO: Look up if there's an interface kinda thing for C++
template<typename T>
class Hook
{
public:
	//TODO: Add base setup fn to set hookFn
	std::string name;
	FunctionUnion_t<T> originalFn;
	FunctionUnion_t<T> hookFn;

	Hook(const char* name);

	virtual void place() = 0;
	virtual void remove() = 0;
};

template<typename T>
class DetourHook : public Hook<T>
{
public:
	FunctionUnion_t<T> tramp;
	size_t size;

	DetourHook(const char* name);
	DetourHook();

	virtual void place();
	virtual void remove();

	bool setup(const Pattern_t& pattern, T hookFn);
	bool setup(const char* name, lm_address_t address, T hookFn);
};

template<typename T>
class VFTHook : public Hook<T>
{
public:
	std::shared_ptr<lm_vmt_t> vft;
	unsigned int index;
	bool hooked;

	VFTHook(const char* name);

	virtual void place();
	virtual void remove();

	void setup(std::shared_ptr<lm_vmt_t> vft, unsigned int index, T hookFn);
};

namespace Hooks
{
	typedef void(*IClientAppManager_RunIPCFrame_t)(void*, void*, void*, void*);
	typedef void(*IClientApps_RunIPCFrame_t)(void*, void*, void*, void*);
	typedef void(*IClientRemoteStorage_RunIPCFrame_t)(void*, void*, void*, void*);
	typedef void(*IClientUGC_RunIPCFrame_t)(void*, void*, void*, void*);
	typedef void(*IClientUtils_RunIPCFrame_t)(void*, void*, void*, void*);
	typedef void(*IClientUser_RunIPCFrame_t)(void*, void*, void*, void*);
	typedef void(*IClientUserStats_RunIPCFrame_t)(void*, void*, void*, void*);

	// 5-arg cdecl generic KV value reader (pObject, foo, KeyName, Key, KeySize),
	// returns bytes written. Steam's depot-key loader.
	typedef int(*LoadDepotDecryptionKey_t)(void*, uint32_t, char*, char*, uint32_t);

	// 8-arg cdecl. arg4 (pDepotInfo) is a CUtlVector<DepotEntry>*; typed as void*
	// here so the header stays decoupled from the sdk layout, the hook casts it.
	typedef bool(*BuildDepotDependency_t)(void*, uint32_t, void*, void*, void*, void*, uint32_t*, bool*);
	// Internal steamclient helper, unofficial name. Plans or refreshes an app's
	// depot download/update work and calls BuildDepotDependency.
	typedef bool(*BUpdateAppDownloadPlan_t)(void*, void*, bool);

	typedef uint32_t(*CAPIJob_GetPlayerStats_t)(void*);

	typedef void(*CProtoBufMsgBase_InitFromPacket_t)(CProtoBufMsgBase*, void*);
	typedef uint32_t(*CProtoBufMsgBase_Send_t)(CProtoBufMsgBase*);

	typedef void(*CSteamEngine_Init_t)(void*);
	typedef uint32_t(*CSteamEngine_SetAppIdForCurrentPipe_t)(void*, uint32_t, bool);

	typedef gameserverdetails_t*(*CSteamMatchmakingServers_GetServerDetails_t)(void*, uint32_t, uint32_t);
	typedef uint32_t(*CSteamMatchmakingServers_RequestInternetServerList_t)(void*, uint32_t, uint32_t, uint32_t, uint32_t);

	typedef uint32_t(*CUser_CheckAppOwnership_t)(void*, uint32_t, CAppOwnershipInfo*);
	typedef uint32_t(*CUser_GetSubscribedApps_t)(void*, uint32_t*, uint32_t, uint8_t);
	typedef bool(*IClientAppManager_BCanRemotePlayTogether_t)(void*, uint32_t);

	typedef bool(*IClientUser_BLoggedOn_t)(void*);
	typedef uint32_t(*IClientUser_BUpdateAppOwnershipTicket_t)(void*, uint32_t, bool);
	typedef uint32_t(*IClientUser_GetAppOwnershipTicketExtendedData_t)(void*, uint32_t, void*, uint32_t, uint32_t*, uint32_t*, uint32_t*, uint32_t*);
	typedef uint8_t(*IClientUser_IsUserSubscribedAppInTicket_t)(void*, uint32_t, uint32_t, uint32_t, uint32_t);
	typedef bool(*IClientUser_RequiresLegacyCDKey_t)(void*, uint32_t, uint32_t*);

	typedef bool(*IClientUtils_GetOfflineMode_t)(void*);

	typedef int    (*MarkLicenseAsChanged_t)(void* pCUser, uint32_t pkgId, uint8_t bChanged);
	typedef bool   (*ProcessPendingLicenseUpdates_t)(void* pCUser);
	typedef void   (*CUtlMemory_Grow_t)(void* pMem, int numToGrowBy);
	extern MarkLicenseAsChanged_t         oMarkLicenseAsChanged;
	extern ProcessPendingLicenseUpdates_t oProcessPendingLicenseUpdates;
	extern CUtlMemory_Grow_t              oCUtlMemoryGrow;

	typedef void* (*CPackageInfo_GetPackageInfo_t)(void*, uint32_t, uint64_t);
	extern DetourHook<CPackageInfo_GetPackageInfo_t> CPackageInfo_GetPackageInfo;

	// steamui.so — CSteamUIAppController::GetAppByID and CUpdateManager::MarkAppChange
	typedef void* (*CSteamUI_GetAppByID_detour_t)(void*, uint32_t, bool);
	typedef void  (*CUpdateManager_MarkAppChange_detour_t)(void*, uint32_t, uint32_t);
	extern DetourHook<CSteamUI_GetAppByID_detour_t>          CSteamUIAppController_GetAppByID;
	extern DetourHook<CUpdateManager_MarkAppChange_detour_t> CUpdateManager_MarkAppChange;

	typedef void* (*CSteamUI_FillInAppOverview_t)(void*, void*, void**);
	extern DetourHook<CSteamUI_FillInAppOverview_t> CSteamUIAppController_FillInAppOverview;

	extern DetourHook<LoadDepotDecryptionKey_t> LoadDepotDecryptionKey;
	extern DetourHook<BuildDepotDependency_t> BuildDepotDependency;
	extern DetourHook<BUpdateAppDownloadPlan_t> BUpdateAppDownloadPlan;

	extern DetourHook<CAPIJob_GetPlayerStats_t> CAPIJob_GetPlayerStats;

	extern DetourHook<CProtoBufMsgBase_InitFromPacket_t> CProtoBufMsgBase_InitFromPacket;
	extern DetourHook<CProtoBufMsgBase_Send_t> CProtoBufMsgBase_Send;

	// Raw packet layer — manifest request-code interception (see requestcode.cpp).
	// (CNetPacket forward-declared at global scope above == ::CNetPacket in sdk/CNetPacket.hpp.)
	typedef bool  (*CWebSocketConnection_BBuildAndAsyncSendFrame_t)(void*, int, uint8_t*, uint32_t);
	typedef void* (*CCMConnection_RecvPkt_t)(void*, CNetPacket*);
	extern DetourHook<CWebSocketConnection_BBuildAndAsyncSendFrame_t> CWebSocketConnection_BBuildAndAsyncSendFrame;
	extern DetourHook<CCMConnection_RecvPkt_t> CCMConnection_RecvPkt;

	extern DetourHook<CSteamMatchmakingServers_GetServerDetails_t> CSteamMatchmakingServers_GetServerDetails;
	extern DetourHook<CSteamMatchmakingServers_RequestInternetServerList_t> CSteamMatchmakingServers_RequestInternetServerList;

	extern DetourHook<IClientAppManager_RunIPCFrame_t> IClientAppManager_RunIPCFrame;
	extern DetourHook<IClientApps_RunIPCFrame_t> IClientApps_RunIPCFrame;
	extern DetourHook<IClientRemoteStorage_RunIPCFrame_t> IClientRemoteStorage_RunIPCFrame;
	extern DetourHook<IClientUGC_RunIPCFrame_t> IClientUGC_RunIPCFrame;
	extern DetourHook<IClientUtils_RunIPCFrame_t> IClientUtils_RunIPCFrame;
	extern DetourHook<IClientUser_RunIPCFrame_t> IClientUser_RunIPCFrame;
	extern DetourHook<IClientUserStats_RunIPCFrame_t> IClientUserStats_RunIPCFrame;

	extern DetourHook<CSteamEngine_Init_t> CSteamEngine_Init;
	extern DetourHook<CSteamEngine_SetAppIdForCurrentPipe_t> CSteamEngine_SetAppIdForCurrentPipe;

	extern DetourHook<CUser_CheckAppOwnership_t> CUser_CheckAppOwnership;
	extern DetourHook<CUser_GetSubscribedApps_t> CUser_GetSubscribedApps;

	extern DetourHook<IClientAppManager_BCanRemotePlayTogether_t> IClientAppManager_BCanRemotePlayTogether;

	extern DetourHook<IClientUser_BLoggedOn_t> IClientUser_BLoggedOn;
	extern DetourHook<IClientUser_BUpdateAppOwnershipTicket_t> IClientUser_BUpdateAppOwnershipTicket;
	extern DetourHook<IClientUser_GetAppOwnershipTicketExtendedData_t> IClientUser_GetAppOwnershipTicketExtendedData;
	extern DetourHook<IClientUser_IsUserSubscribedAppInTicket_t> IClientUser_IsUserSubscribedAppInTicket;
	extern DetourHook<IClientUser_RequiresLegacyCDKey_t> IClientUser_RequiresLegacyCDKey;

	typedef bool(*IClientAppManager_BIsDlcEnabled_t)(void*, uint32_t, uint32_t, void*);
	typedef bool(*IClientAppManager_GetAppUpdateInfo_t)(void*, uint32_t, uint32_t*);
	typedef void*(*IClientAppManager_LaunchApp_t)(void*, uint32_t*, void*, void*, void*);
	typedef bool(*IClientAppManager_IsAppDlcInstalled_t)(void*, uint32_t, uint32_t);
	typedef unsigned int(*IClientApps_GetDLCCount_t)(void*, uint32_t);
	typedef bool(*IClientApps_BGetDLCDataByIndex_t)(void*, uint32_t, int, uint32_t*, bool*, char*, size_t);
	typedef bool(*IClientRemoteStorage_IsCloudEnabledForApp_t)(void*, uint32_t);
	typedef uint32_t(*IClientUtils_GetAppId_t)(void*);
	typedef uint32_t(*CConfigStore_WriteVdfFile_t)(void*, uint32_t, uint32_t, void*, const char*, uint32_t);

	extern VFTHook<IClientAppManager_BIsDlcEnabled_t> IClientAppManager_BIsDlcEnabled;
	extern VFTHook<IClientAppManager_GetAppUpdateInfo_t> IClientAppManager_GetAppUpdateInfo;
	extern VFTHook<IClientAppManager_LaunchApp_t> IClientAppManager_LaunchApp;
	extern VFTHook<IClientAppManager_IsAppDlcInstalled_t> IClientAppManager_IsAppDlcInstalled;

	extern VFTHook<IClientApps_BGetDLCDataByIndex_t> IClientApps_BGetDLCDataByIndex;
	extern VFTHook<IClientApps_GetDLCCount_t> IClientApps_GetDLCCount;

	extern VFTHook<IClientRemoteStorage_IsCloudEnabledForApp_t> IClientRemoteStorage_IsCloudEnabledForApp;
	extern DetourHook<CConfigStore_WriteVdfFile_t> CConfigStore_WriteVdfFile;

	extern VFTHook<IClientUtils_GetAppId_t> IClientUtils_GetAppId;
	extern VFTHook<IClientUtils_GetOfflineMode_t> IClientUtils_GetOfflineMode;

	typedef void(*ISteamMatchmakingPingResponse_ServerResponded_t)(void*, gameserverdetails_t*);


	//steamui.so
	extern DetourHook<ISteamMatchmakingPingResponse_ServerResponded_t> ISteamMatchmakingPingResponse_ServerResponded;


	//Naked
	extern lm_address_t IClientUser_GetSteamId;

	bool setup();
	void place();
	void remove();
}
