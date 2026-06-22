#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <string>

class CMsgClientGetAppOwnershipTicketResponse;
class CMsgClientRequestEncryptedAppTicketResponse;
class CProtoBufMsgBase;

namespace Ticket
{
	class SavedTicket
	{
public:
		uint32_t steamId;
		std::string ticket;
	};

	// Atomic: written by getTicketOwnershipExtendedData (one hook thread) and
	// read-and-cleared by hkClientUser_GetSteamId (another) — exchange() keeps
	// the one-time semantics without a torn/lost-update data race.
	extern std::atomic<uint32_t> oneTimeSteamIdSpoof;
	extern std::map<uint32_t, SavedTicket> ticketMap;
	extern std::map<uint32_t, SavedTicket> encryptedTicketMap;

	std::string getTicketDir();

	//TODO: Fill with error checks
	std::string getTicketPath(uint32_t appId);
	SavedTicket getCachedTicket(uint32_t appId);
	bool saveTicketToCache(CMsgClientGetAppOwnershipTicketResponse* resp);

	void launchApp(uint32_t appId);
	// Called from DetourHook. If original returned a valid ticket, caches raw
	// bytes + offsets to disk. If original returned empty, replays from cache
	// (or falls back to ForgeTicket). Returns overridden size, or 0 to keep
	// the original return value.
	uint32_t getTicketOwnershipExtendedData(
		uint32_t appId, void* pTicket, uint32_t ticketSize,
		uint32_t* piAppId, uint32_t* piSteamId,
		uint32_t* piSignature, uint32_t* pcbSignature,
		void* pClientUser);

	std::string getEncryptedTicketPath(uint32_t appId);
	SavedTicket getCachedEncryptedTicket(uint32_t appId);
	bool saveEncryptedTicketToCache(CMsgClientRequestEncryptedAppTicketResponse* resp);

	void recvEncryptedAppTicket(CMsgClientRequestEncryptedAppTicketResponse* msg);
	void recvAppTicket(CMsgClientGetAppOwnershipTicketResponse* msg);
	bool onSendFrame(const uint8_t* pubData, uint32_t cubData);
	void recvMsg(CProtoBufMsgBase* msg);
}
