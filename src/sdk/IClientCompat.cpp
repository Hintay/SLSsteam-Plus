#include "IClientCompat.hpp"

#include "../ipcoutbound.hpp"
#include "../vtablescan.hpp"

#include <cstdint>

const char* IClientCompat::getCompatToolName(uint32_t appId)
{
	static const int idx = VtableScan::slotOf("IClientCompat", "GetCompatToolName");
	if (idx < 0) return nullptr;
	return IpcOutbound::callAt<const char*(*)(void*, uint32_t)>(idx, this, appId);
}

IClientCompat* g_pClientCompat = nullptr;
