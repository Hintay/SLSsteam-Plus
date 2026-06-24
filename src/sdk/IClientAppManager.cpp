#include "IClientAppManager.hpp"

#include "../ipcoutbound.hpp"
#include "../vftableinfo.gen.hpp"

#include <cstdint>

// Outbound calls use RE-confirmed vtable indexes as primary. The IPC funcHash
// selector is still generated for diagnostics/online fallback, but it drifts.
EAppUpdateError IClientAppManager::installApp(uint32_t appId, int32_t libraryIndex)
{
	static const int idx = VFTIndexes::IClientAppManager::InstallApp();
	return IpcOutbound::callAt<EAppUpdateError(*)(void*, uint32_t, int32_t, uint8_t)>(idx, this, appId, libraryIndex, 0);
}

EAppState IClientAppManager::getAppInstallState(uint32_t appId)
{
	static const int idx = VFTIndexes::IClientAppManager::GetAppInstallState();
	return IpcOutbound::callAt<EAppState(*)(void*, uint32_t)>(idx, this, appId);
}

IClientAppManager* g_pClientAppManager;
