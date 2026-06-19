#include "IClientAppManager.hpp"

#include "../ipchash.gen.hpp"
#include "../ipcoutbound.hpp"

#include <cstdint>

// Outbound vtable index resolved from the build-stable funcHash (cached per call site); no
// hardcoded fallback — a resolve miss skips the call and returns a value-initialized result.
EAppUpdateError IClientAppManager::installApp(uint32_t appId, int32_t libraryIndex)
{
	static const int idx = IpcOutbound::resolveIndex(IpcHash::IClientAppManager::kInstallApp_Name, IpcHash::IClientAppManager::kInstallApp);
	if (idx < 0) return {};
	return IpcOutbound::callAt<EAppUpdateError(*)(void*, uint32_t, int32_t, uint8_t)>(idx, this, appId, libraryIndex, 0);
}

EAppState IClientAppManager::getAppInstallState(uint32_t appId)
{
	static const int idx = IpcOutbound::resolveIndex(IpcHash::IClientAppManager::kGetAppInstallState_Name, IpcHash::IClientAppManager::kGetAppInstallState);
	if (idx < 0) return {};
	return IpcOutbound::callAt<EAppState(*)(void*, uint32_t)>(idx, this, appId);
}

IClientAppManager* g_pClientAppManager;
