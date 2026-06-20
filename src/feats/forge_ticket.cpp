#include "forge_ticket.hpp"
#include "ticket.hpp"

#include "../hooks.hpp"
#include "../log.hpp"
#include "../ownership.hpp"

#include <cstring>
#include <mutex>

namespace {

std::once_flag  g_sourceOnce;
std::vector<uint8_t> g_sourceTicket;

void doAcquireSource(void* pClientUser)
{
	constexpr uint32_t kBufSize = 2048;
	uint8_t buf[kBufSize];
	uint32_t piAppId = 0, piSteamId = 0, piSig = 0, pcbSig = 0;

	const uint32_t ret = Hooks::IClientUser_GetAppOwnershipTicketExtendedData.tramp.fn(
		pClientUser, ForgeTicket::kSourceAppId,
		buf, kBufSize, &piAppId, &piSteamId, &piSig, &pcbSig);

	if (ret == 0 || ret > kBufSize)
	{
		g_pLog->warn("ForgeTicket: source ticket (appid %u) unavailable (ret=%u)\n",
			ForgeTicket::kSourceAppId, ret);
		return;
	}

	g_sourceTicket.assign(buf, buf + ret);
	g_pLog->info("ForgeTicket: cached source ticket (%u bytes) from appid %u\n",
		ret, ForgeTicket::kSourceAppId);
}

std::vector<uint8_t> forgeLocal(uint32_t appId)
{
	if (g_sourceTicket.size() <= ForgeTicket::kAppTicketSignatureSize)
		return {};

	const size_t signedSize = g_sourceTicket.size() - ForgeTicket::kAppTicketSignatureSize;

	std::vector<uint8_t> ticket;
	ticket.reserve(g_sourceTicket.size() + sizeof(uint32_t));
	ticket.insert(ticket.end(), g_sourceTicket.begin(), g_sourceTicket.begin() + signedSize);

	const uint8_t* appIdBytes = reinterpret_cast<const uint8_t*>(&appId);
	ticket.insert(ticket.end(), appIdBytes, appIdBytes + sizeof(uint32_t));

	ticket.insert(ticket.end(), g_sourceTicket.begin() + signedSize, g_sourceTicket.end());

	return ticket;
}

}

void ForgeTicket::acquireSourceTicket(void* pClientUser)
{
	std::call_once(g_sourceOnce, doAcquireSource, pClientUser);
}

bool ForgeTicket::getAppOwnershipTicket(uint32_t appId, AppOwnershipTicket& ticket)
{
	ticket = {};

	// Priority 1: cached ticket (lua > runtime cache > disk)
	Ticket::SavedTicket cached = Ticket::getCachedTicket(appId);
	if (!cached.ticket.empty() && cached.ticket.size() >= sizeof(uint32_t))
	{
		ticket.data.assign(cached.ticket.begin(), cached.ticket.end());
		ticket.totalSize      = static_cast<uint32_t>(ticket.data.size());
		ticket.appIdOffset    = kAppTicketAppIdOffset;
		ticket.steamIdOffset  = kAppTicketSteamIdOffset;
		ticket.signatureOffset = *reinterpret_cast<const uint32_t*>(ticket.data.data());
		ticket.signatureSize  = kAppTicketSignatureSize;
		return true;
	}

	// Priority 2: forge from appid 7
	std::vector<uint8_t> forged = forgeLocal(appId);
	if (forged.empty())
		return false;

	ticket.data          = std::move(forged);
	ticket.totalSize     = static_cast<uint32_t>(ticket.data.size() - sizeof(uint32_t));
	ticket.appIdOffset   = ticket.totalSize - kAppTicketSignatureSize;
	ticket.signatureOffset = ticket.appIdOffset + sizeof(uint32_t);
	ticket.steamIdOffset = kAppTicketSteamIdOffset;
	ticket.signatureSize = kAppTicketSignatureSize;
	return true;
}
