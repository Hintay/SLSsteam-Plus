#include "CSteamEngine.hpp"

#include "../hooks.hpp"
#include "../patterns.hpp"

#include "libmem/libmem.h"

#include <cstring>

namespace
{
	uint32_t readUnalignedU32(lm_address_t address)
	{
		uint32_t value = 0;
		memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value));
		return value;
	}
}

CUser* CSteamEngine::getUser(uint32_t index)
{
	// Caller must verify g_pSteamEngine != nullptr; a member-function null
	// check on `this` is UB-deleted at -O3 (-Wnonnull-compare).
	if (Patterns::CSteamEngine::Offset_User.address == LM_ADDRESS_BAD)
		return nullptr;

	const static auto offset = readUnalignedU32(Patterns::CSteamEngine::Offset_User.address + 0x2);
	if (!offset)
		return nullptr;

	const auto ppUserMap = *reinterpret_cast<uint8_t**>(reinterpret_cast<uint8_t*>(this) + offset);
	if (!ppUserMap)
		return nullptr;

	const auto ppUser = ppUserMap + index * 8;

	return *reinterpret_cast<CUser**>(ppUser + 4);
}

void CSteamEngine::setAppIdForCurrentPipe(uint32_t appId)
{
	//Last argument needs to be 0, otherwise steam crashes.
	//Might be only 1 when steam first sets it, then 0
	Hooks::CSteamEngine_SetAppIdForCurrentPipe.tramp.fn(this, appId, 0);
}

CSteamEngine* g_pSteamEngine = nullptr;
