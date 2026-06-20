#pragma once

#include <cstdint>
#include <vector>

namespace ForgeTicket
{

constexpr uint32_t kAppTicketSteamIdOffset  = 8;
constexpr uint32_t kAppTicketAppIdOffset    = 16;
constexpr uint32_t kAppTicketSignatureSize  = 128;
constexpr uint32_t kSourceAppId             = 7;

struct AppOwnershipTicket
{
	std::vector<uint8_t> data;
	uint32_t totalSize       = 0;
	uint32_t appIdOffset     = kAppTicketAppIdOffset;
	uint32_t steamIdOffset   = kAppTicketSteamIdOffset;
	uint32_t signatureOffset = 0;
	uint32_t signatureSize   = kAppTicketSignatureSize;
};

// Try to build an AppOwnershipTicket for appId.
// Priority: cached ticket (lua > runtime > disk) → forge from appid 7.
// Returns false if no ticket can be produced.
bool getAppOwnershipTicket(uint32_t appId, AppOwnershipTicket& ticket);

// Acquire the source ticket (appid 7) from Steam's runtime cache.
// Called lazily on first forge attempt. Thread-safe (std::call_once).
// pClientUser: the IClientUser pointer from the IPC handler context.
void acquireSourceTicket(void* pClientUser);

}
