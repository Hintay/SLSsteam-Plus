#include "IClientUtils.hpp"

#include "../hooks.hpp"
#include "../memhlp.hpp"
#include "../patterns.hpp"

#include "libmem/libmem.h"

#include <cstdint>

uint32_t* IClientUtils::getPipeIndex()
{
	//Offset found in IClientUtils::GetAppId
	const static auto offset = *reinterpret_cast<lm_address_t*>(Patterns::IClientUtils::Offset_GetPipeIndex.address + 0x2);
	return reinterpret_cast<uint32_t*>(this + offset);
}


uint32_t IClientUtils::getAppId()
{
	return Hooks::IClientUtils_GetAppId.originalFn.fn(this);
}

IClientUtils* g_pClientUtils;
