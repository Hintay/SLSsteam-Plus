#include "IClientAppManager.hpp"

#include "../ipcoutbound.hpp"
#include "../vtablescan.hpp"

#include <cstdint>

// Outbound calls resolve their vtable slot via VtableScan at first use. The slot
// comes from the live IClientAppManagerMap vtable's own typeinfo + slot-decoded
// internal method name, so no patterns.toml vft_index entry is involved.
EAppUpdateError IClientAppManager::installApp(uint32_t appId, int32_t libraryIndex)
{
	static const int idx = VtableScan::slotOf("IClientAppManager", "InstallApp");
	return IpcOutbound::callAt<EAppUpdateError(*)(void*, uint32_t, int32_t, uint8_t)>(idx, this, appId, libraryIndex, 0);
}

EAppState IClientAppManager::getAppInstallState(uint32_t appId)
{
	static const int idx = VtableScan::slotOf("IClientAppManager", "GetAppInstallState");
	return IpcOutbound::callAt<EAppState(*)(void*, uint32_t)>(idx, this, appId);
}

IClientAppManager* g_pClientAppManager;
