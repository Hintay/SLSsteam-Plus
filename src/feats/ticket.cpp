#include "ticket.hpp"

#include "fakeappid.hpp"
#include "forge_ticket.hpp"

#include "../config.hpp"
#include "../globals.hpp"
#include "../lua/LuaLoader.hpp"
#include "../ownership.hpp"

#include "../sdk/CProtoBufMsgBase.hpp"
#include "../sdk/RawNetPacket.hpp"
#include "../sdk/CSteamEngine.hpp"
#include "../sdk/CUser.hpp"
#include "../sdk/EResult.hpp"
#include "../sdk/IClientUtils.hpp"

#include "base64/base64.hpp"
#include <toml++/toml.hpp>

#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <mutex>
#include <sstream>

std::atomic<uint32_t> Ticket::oneTimeSteamIdSpoof{0};
std::map<uint32_t, Ticket::SavedTicket> Ticket::ticketMap = std::map<uint32_t, SavedTicket>();
std::map<uint32_t, Ticket::SavedTicket> Ticket::encryptedTicketMap = std::map<uint32_t, SavedTicket>();

// Guards ticketMap / encryptedTicketMap. getCached*/save* run on both the
// network-recv hook thread and the IPC/launch hook thread, and std::map is not
// safe for concurrent insert+read (red-black tree rebalance corrupts a reader).
static std::mutex ticketMapMutex;

static bool applyLuaEncryptedTicketResponse(uint32_t appId, CMsgClientRequestEncryptedAppTicketResponse* msg)
{
	const auto luaTkt = LuaLoader::getEncTicket(appId);
	if (!luaTkt)
	{
		return false;
	}

	msg->Clear();
	msg->set_app_id(appId);
	msg->set_eresult(ERESULT_OK);
	msg->mutable_encrypted_app_ticket()->set_encrypted_ticket(luaTkt->bytes.data(), luaTkt->bytes.size());
	g_pLog->debug("Using lua encrypted ticket response for %u (%zu bytes)\n", appId, luaTkt->bytes.size());
	return true;
}

std::string Ticket::getTicketDir()
{
	std::stringstream ss;
	ss << g_config.getDir().c_str() << "/cache";

	const auto dir = ss.str();
	if (!std::filesystem::exists(dir.c_str()))
	{
		std::filesystem::create_directory(dir.c_str());
	}

	return ss.str();
}

std::string Ticket::getTicketPath(uint32_t appId)
{
	std::stringstream ss;
	ss << getTicketDir().c_str() << "/ticket_" << appId << ".toml";

	return ss.str();
}

Ticket::SavedTicket Ticket::getCachedTicket(uint32_t appId)
{
	// Lua-provided tickets take priority over the runtime cache and disk.
	// They live only in memory — no disk read/write.
	const auto luaTkt = LuaLoader::getAppTicket(appId);
	if (luaTkt)
	{
		g_pLog->debug("Using lua app ticket for %u (steamId=0x%08x)\n", appId, luaTkt->steamId);
		SavedTicket ticket {};
		ticket.steamId = luaTkt->steamId;
		ticket.ticket  = std::string(luaTkt->bytes.begin(), luaTkt->bytes.end());
		// Intentionally NOT stored in ticketMap: lua tickets must stay in-memory
		// only, or they would survive removal of the .lua file that defined them.
		return ticket;
	}

	{
		std::lock_guard<std::mutex> lock(ticketMapMutex);
		const auto it = ticketMap.find(appId);
		if (it != ticketMap.end())
		{
			return it->second;
		}
	}

	SavedTicket ticket {};

	const auto path = getTicketPath(appId);
	if (!std::filesystem::exists(path.c_str()))
	{
		return ticket;
	}

	g_pLog->debug("Reading ticket for %u\n", appId);

	try
	{
		auto tbl = toml::parse_file(path);
		ticket.steamId = static_cast<uint32_t>(tbl["steamId"].value_or(int64_t(0)));
		ticket.ticket = std::string
		(
			base64::from_base64(tbl["ticket"].value_or(std::string()))
		);
	}
	catch (const std::exception& e)
	{
		// Corrupt/hand-edited cache file: don't let a parse/base64 exception unwind
		// through the Steam hook thread (→ std::terminate). Treat it as a miss.
		g_pLog->warn("Ticket: failed to parse cached ticket for %u: %s\n", appId, e.what());
		return SavedTicket {};
	}

	{
		std::lock_guard<std::mutex> lock(ticketMapMutex);
		ticketMap[appId] = ticket;
	}

	return ticket;
}

bool Ticket::saveTicketToCache(CMsgClientGetAppOwnershipTicketResponse* resp)
{
	const uint32_t appId = resp->app_id();

	g_pLog->debug("Saving ticket for %u...\n", appId);

	// Do not write to disk if a lua-provided ticket is registered for this app.
	// The lua ticket wins; writing the real ticket would go stale if the .lua
	// file is later removed or edited.
	if (LuaLoader::getAppTicket(appId))
	{
		g_pLog->debug("Skipping disk write for ticket %u — lua ticket takes priority\n", appId);
		return true;
	}

	auto bytes = resp->ticket();

	const auto path = Ticket::getTicketPath(appId);
	std::ofstream ofs(path.c_str(), std::ios::out);
	ofs << "steamId = " << g_currentSteamId << "\n"
	    << "ticket = \"" << base64::to_base64(bytes) << "\"\n";

	g_pLog->once("Saved ticket for %u\n", appId);

	//TODO: Skip copy
	SavedTicket ticket {};
	ticket.steamId = g_currentSteamId;
	ticket.ticket = bytes;
	{
		std::lock_guard<std::mutex> lock(ticketMapMutex);
		ticketMap[appId] = ticket;
	}

	return true;
}

void Ticket::launchApp(uint32_t appId)
{
	auto ticket = getCachedTicket(appId);
	if (!ticket.ticket.size())
		return;

	g_pSteamEngine->getUser(0)->updateAppOwnershipTicket(appId, reinterpret_cast<void*>(ticket.ticket.data()), ticket.ticket.size());
	g_pLog->once("Force loaded AppOwnershipTicket for %i\n", appId);
}

// On-disk cache path for the raw extended ticket data (binary, upstream style).
static std::string getExtendedTicketPath(uint32_t appId)
{
	std::stringstream ss;
	ss << Ticket::getTicketDir() << "/ticketExtended_" << appId;
	return ss.str();
}

// Fixed-layout binary cache matching the upstream CTicketData scheme.
#pragma pack(push, 1)
struct ExtendedTicketCache
{
	uint32_t steamId;
	uint32_t appId;
	char     ticket[0x400];
	uint32_t size;
	uint32_t extraData[4]; // piAppId, piSteamId, piSignature, pcbSignature
};
#pragma pack(pop)

static bool saveExtendedTicketToCache(
	uint32_t appId, uint32_t steamId,
	const void* ticketData, uint32_t ticketSize,
	uint32_t piAppId, uint32_t piSteamId,
	uint32_t piSignature, uint32_t pcbSignature)
{
	if (ticketSize > sizeof(ExtendedTicketCache::ticket))
	{
		g_pLog->warn("ExtendedTicket: ticket too large (%u) for cache of appid %u\n", ticketSize, appId);
		return false;
	}

	ExtendedTicketCache cache {};
	cache.steamId = steamId;
	cache.appId   = appId;
	std::memcpy(cache.ticket, ticketData, ticketSize);
	cache.size = ticketSize;
	cache.extraData[0] = piAppId;
	cache.extraData[1] = piSteamId;
	cache.extraData[2] = piSignature;
	cache.extraData[3] = pcbSignature;

	const auto path = getExtendedTicketPath(appId);
	std::ofstream ofs(path, std::ios::out | std::ios::binary);
	if (!ofs.is_open()) return false;
	ofs.write(reinterpret_cast<const char*>(&cache), sizeof(cache));
	g_pLog->once("ExtendedTicket: cached ticket for appid %u (%u bytes)\n", appId, ticketSize);
	return true;
}

static bool loadExtendedTicketFromCache(uint32_t appId, ExtendedTicketCache& out)
{
	const auto path = getExtendedTicketPath(appId);
	if (!std::filesystem::exists(path)) return false;

	std::ifstream ifs(path, std::ios::in | std::ios::binary);
	if (!ifs.is_open()) return false;
	ifs.read(reinterpret_cast<char*>(&out), sizeof(out));
	if (ifs.gcount() != sizeof(out)) return false;
	return out.size > 0 && out.size <= sizeof(out.ticket);
}

uint32_t Ticket::getTicketOwnershipExtendedData(
	uint32_t appId, void* pTicket, uint32_t ticketSize,
	uint32_t* piAppId, uint32_t* piSteamId,
	uint32_t* piSignature, uint32_t* pcbSignature,
	void* pClientUser)
{
	if (ticketSize)
	{
		// Original returned a valid ticket — cache it (upstream behaviour).
		saveExtendedTicketToCache(appId, g_currentSteamId, pTicket, ticketSize,
			piAppId  ? *piAppId  : 0, piSteamId   ? *piSteamId   : 0,
			piSignature ? *piSignature : 0, pcbSignature ? *pcbSignature : 0);
		return 0;
	}

	// No ticket from original. Try disk cache first (upstream replay).
	ExtendedTicketCache cached {};
	if (loadExtendedTicketFromCache(appId, cached))
	{
		std::memcpy(pTicket, cached.ticket, cached.size);
		if (piAppId)      *piAppId      = cached.extraData[0];
		if (piSteamId)    *piSteamId    = cached.extraData[1];
		if (piSignature)  *piSignature  = cached.extraData[2];
		if (pcbSignature) *pcbSignature = cached.extraData[3];

		oneTimeSteamIdSpoof = cached.steamId;
		g_pLog->info("ExtendedTicket: replayed cached ticket for appid %u (%u bytes, steamId=%u)\n",
			appId, cached.size, cached.steamId);
		return cached.size;
	}

	// No cache — fall back to ForgeTicket.
	if (!Ownership::shouldSpoofOwnership(appId))
		return 0;

	ForgeTicket::acquireSourceTicket(pClientUser);

	ForgeTicket::AppOwnershipTicket forged{};
	if (!ForgeTicket::getAppOwnershipTicket(appId, forged))
		return 0;

	if (forged.data.size() > 0x400)
		return 0;

	std::memcpy(pTicket, forged.data.data(), forged.data.size());
	if (piAppId)      *piAppId      = forged.appIdOffset;
	if (piSteamId)    *piSteamId    = forged.steamIdOffset;
	if (piSignature)  *piSignature  = forged.signatureOffset;
	if (pcbSignature) *pcbSignature = forged.signatureSize;

	if (forged.data.size() >= 16)
	{
		uint64_t sid64 = 0;
		std::memcpy(&sid64, forged.data.data() + ForgeTicket::kAppTicketSteamIdOffset, sizeof(uint64_t));
		oneTimeSteamIdSpoof = static_cast<uint32_t>(sid64 & 0xFFFFFFFFULL);
	}

	g_pLog->info("ExtendedTicket: forged ticket for appid %u (totalSize=%u)\n",
		appId, forged.totalSize);
	return forged.totalSize;
}

std::string Ticket::getEncryptedTicketPath(uint32_t appId)
{
	std::stringstream ss;
	ss << getTicketDir().c_str() << "/encryptedTicket_" << appId << ".toml";

	return ss.str();
}

Ticket::SavedTicket Ticket::getCachedEncryptedTicket(uint32_t appId)
{
	const uint32_t realAppId = FakeAppIds::getRealAppIdForCurrentPipe();
	const uint32_t fakeAppId = FakeAppIds::getFakeAppId(realAppId);

	SavedTicket ticket {};

	// Lua-provided encrypted tickets take priority over the runtime cache, disk,
	// and fake-app-id remapping — same ordering as getCachedTicket so a script
	// that registered a ticket via seteticket is honoured even when the app is
	// subject to fake-app-id remapping. steamId is 0 for encrypted tickets (no
	// plaintext SteamID available), so the GetSteamId hook falls back to
	// oneTimeSteamIdSpoof from the app ticket path. recvEncryptedAppTicket wraps
	// these raw lua bytes into a CMsgClientRequestEncryptedAppTicketResponse.
	const auto luaTkt = LuaLoader::getEncTicket(appId);
	if (luaTkt)
	{
		g_pLog->debug("Using lua encrypted ticket for %u\n", appId);
		ticket.steamId = luaTkt->steamId; // 0 for encrypted tickets
		ticket.ticket  = std::string(luaTkt->bytes.begin(), luaTkt->bytes.end());
		// In-memory only, same rule as the app-ticket path above.
		return ticket;
	}

	if (realAppId && fakeAppId && appId != realAppId)
	{
		g_pLog->once("Returning empty cached encrypted ticket for %u because it's set to %u\n", realAppId, fakeAppId);
		return ticket;
	}

	{
		std::lock_guard<std::mutex> lock(ticketMapMutex);
		const auto it = encryptedTicketMap.find(appId);
		if (it != encryptedTicketMap.end())
		{
			return it->second;
		}
	}

	const auto path = getEncryptedTicketPath(appId);
	if (!std::filesystem::exists(path.c_str()))
	{
		return ticket;
	}

	g_pLog->debug("Reading encrypted ticket for %u\n", appId);

	try
	{
		auto tbl = toml::parse_file(path);
		ticket.steamId = static_cast<uint32_t>(tbl["steamId"].value_or(int64_t(0)));
		ticket.ticket = std::string
		(
			base64::from_base64(tbl["encryptedTicket"].value_or(std::string()))
		);
	}
	catch (const std::exception& e)
	{
		g_pLog->warn("Ticket: failed to parse cached encrypted ticket for %u: %s\n", appId, e.what());
		return SavedTicket {};
	}

	{
		std::lock_guard<std::mutex> lock(ticketMapMutex);
		encryptedTicketMap[appId] = ticket;
	}

	return ticket;
}

bool Ticket::saveEncryptedTicketToCache(CMsgClientRequestEncryptedAppTicketResponse* resp)
{
	const uint32_t appId = resp->app_id();

	g_pLog->debug("Saving encrypted ticket for %u...\n", appId);

	// Do not write to disk if a lua-provided encrypted ticket is registered.
	// The lua ticket wins; the real auto-cached ticket must not clobber it.
	if (LuaLoader::getEncTicket(appId))
	{
		g_pLog->debug("Skipping disk write for encrypted ticket %u — lua ticket takes priority\n", appId);
		return true;
	}

	auto bytes = resp->SerializeAsString();

	const auto path = getEncryptedTicketPath(appId);
	std::ofstream ofs(path.c_str(), std::ios::out);
	ofs << "steamId = " << g_currentSteamId << "\n"
	    << "encryptedTicket = \"" << base64::to_base64(bytes) << "\"\n";

	g_pLog->once("Saved encrypted ticket for %u\n", appId);

	//TODO: Skip copy
	SavedTicket ticket {};
	ticket.steamId = g_currentSteamId;
	ticket.ticket = bytes;
	{
		std::lock_guard<std::mutex> lock(ticketMapMutex);
		encryptedTicketMap[appId] = ticket;
	}
	
	return true;
}

void Ticket::recvEncryptedAppTicket(CMsgClientRequestEncryptedAppTicketResponse* msg)
{
	if (msg->eresult() == ERESULT_OK)
	{
		saveEncryptedTicketToCache(msg);
		return;
	}

	const uint32_t appId = msg->app_id();
	if (applyLuaEncryptedTicketResponse(appId, msg))
	{
		return;
	}

	SavedTicket ticket = getCachedEncryptedTicket(appId);
	// Disk/runtime cache entries are complete serialized response protobufs and
	// carry the SteamID captured when they were saved. steamId==0 means no replayable
	// cached response is available.
	if(!ticket.steamId)
	{
		return;
	}

	msg->ParseFromString(ticket.ticket);
	g_pLog->debug("Using encryptedTicket_%u from disk\n", appId);
}

void Ticket::recvAppTicket(CMsgClientGetAppOwnershipTicketResponse* msg)
{
	if(msg->eresult() == ERESULT_OK)
	{
		saveTicketToCache(msg);
		return;
	}

	//We do not load tickets from disk in the network layer, otherwise they won't be loaded in offline mode
}

bool Ticket::onSendFrame(const uint8_t* pubData, uint32_t cubData)
{
	netpacket::RawPacketView packet;
	if (!netpacket::UnpackRaw(pubData, cubData, packet))
	{
		return false;
	}

	if (packet.eMsg != EMSG_APPOWNERSHIPTICKET_REQUEST)
	{
		return false;
	}

	CMsgClientGetAppOwnershipTicket body;
	if (!body.ParseFromArray(packet.body, static_cast<int>(packet.bodySize)))
	{
		g_pLog->warn("Ticket: raw AppOwnershipTicket request has unparsable body (hdr=%u body=%u)\n", packet.headerSize, packet.bodySize);
		return false;
	}

	const uint32_t appId = body.app_id();
	const bool spoofedOwnership = Ownership::shouldSpoofOwnership(appId);
	g_pLog->debug
	(
		"Ticket: raw AppOwnershipTicket frame appId=%u spoofed=%i size=%u\n",

		appId,
		spoofedOwnership,
		cubData
	);

	if (!spoofedOwnership)
		return false;

	SavedTicket cached = Ticket::getCachedTicket(appId);
	auto* user = g_pSteamEngine ? g_pSteamEngine->getUser(0) : nullptr;
	if (user && !cached.ticket.empty())
	{
		user->updateAppOwnershipTicket(appId, reinterpret_cast<void*>(cached.ticket.data()), cached.ticket.size());
		g_pLog->once("Loaded local AppOwnershipTicket for %u (%zu bytes)\n", appId, cached.ticket.size());
	}

	if (!g_config.blockTicketRequests.get())
		return false;

	g_pLog->once("Dropped raw AppOwnershipTicket request for fake-owned AppID %u\n", appId);
	return true;
}

void Ticket::recvMsg(CProtoBufMsgBase* msg)
{
	switch(msg->type)
	{
		case EMSG_APPOWNERSHIPTICKET_RESPONSE:
			recvAppTicket(msg->getBody<CMsgClientGetAppOwnershipTicketResponse>());
			break;

		case EMSG_ENCRYPTED_APPTICKET_RESPONSE:
			recvEncryptedAppTicket(msg->getBody<CMsgClientRequestEncryptedAppTicketResponse>());
			break;
	}
}
