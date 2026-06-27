#include "IClientApps.hpp"

#include "../ipcoutbound.hpp"
#include "../vtablescan.hpp"

#include <cstdint>

// Outbound calls resolve their vtable slot via VtableScan at first use. See
// IClientAppManager.cpp for the rationale.
int32_t IClientApps::getAppData(uint32_t appId, const char* name, char* pChOut, uint32_t outSize)
{
	static const int idx = VtableScan::slotOf("IClientApps", "GetAppData");
	return IpcOutbound::callAt<int32_t(*)(void*, uint32_t, const char*, char*, uint32_t)>(idx, this, appId, name, pChOut, outSize);
}

int32_t IClientApps::getAppDataSection(uint32_t appId, EAppInfoSection section, char* pChOut, uint32_t outSize, bool bSharedKVSymbols)
{
	static const int idx = VtableScan::slotOf("IClientApps", "GetAppDataSection");
	return IpcOutbound::callAt<int32_t(*)(void*, uint32_t, uint32_t, char*, uint32_t, uint8_t)>(idx, this, appId, section, pChOut, outSize, bSharedKVSymbols ? 1 : 0);
}

bool IClientApps::requestAppInfoUpdate(uint32_t appId)
{
	static const int idx = VtableScan::slotOf("IClientApps", "RequestAppInfoUpdate");
	uint32_t ids[1] = { appId };
	return IpcOutbound::callAt<bool(*)(void*, uint32_t*, int)>(idx, this, ids, 1);
}

EAppType IClientApps::getAppType(uint32_t appId)
{
	static const int idx = VtableScan::slotOf("IClientApps", "GetAppType");
	return IpcOutbound::callAt<EAppType(*)(void*, uint32_t)>(idx, this, appId);
}

IClientApps* g_pClientApps;
