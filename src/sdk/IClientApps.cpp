#include "IClientApps.hpp"

#include "../ipchash.gen.hpp"
#include "../ipcoutbound.hpp"

#include <cstdint>

// Outbound calls resolve their vtable index from the build-stable funcHash (drift-immune); the
// index is cached once per call site in a function-local static. No hardcoded fallback: on a
// resolve miss the call is skipped and a value-initialized result returned.
int32_t IClientApps::getAppData(uint32_t appId, const char* name, char* pChOut, uint32_t outSize)
{
	static const int idx = IpcOutbound::resolveIndex(IpcHash::IClientApps::kGetAppData_Name, IpcHash::IClientApps::kGetAppData);
	if (idx < 0) return {};
	return IpcOutbound::callAt<int32_t(*)(void*, uint32_t, const char*, char*, uint32_t)>(idx, this, appId, name, pChOut, outSize);
}

int32_t IClientApps::getAppDataSection(uint32_t appId, EAppInfoSection section, char* pChOut, uint32_t outSize)
{
	static const int idx = IpcOutbound::resolveIndex(IpcHash::IClientApps::kGetAppDataSection_Name, IpcHash::IClientApps::kGetAppDataSection);
	if (idx < 0) return {};
	return IpcOutbound::callAt<int32_t(*)(void*, uint32_t, uint32_t, char*, uint32_t, uint8_t)>(idx, this, appId, section, pChOut, outSize, 1);
}

bool IClientApps::requestAppInfoUpdate(uint32_t appId)
{
	static const int idx = IpcOutbound::resolveIndex(IpcHash::IClientApps::kRequestAppInfoUpdate_Name, IpcHash::IClientApps::kRequestAppInfoUpdate);
	if (idx < 0) return {};
	uint32_t ids[1] = { appId };
	return IpcOutbound::callAt<bool(*)(void*, uint32_t*, int)>(idx, this, ids, 1);
}

EAppType IClientApps::getAppType(uint32_t appId)
{
	static const int idx = IpcOutbound::resolveIndex(IpcHash::IClientApps::kGetAppType_Name, IpcHash::IClientApps::kGetAppType);
	if (idx < 0) return {};
	return IpcOutbound::callAt<EAppType(*)(void*, uint32_t)>(idx, this, appId);
}

IClientApps* g_pClientApps;
