#pragma once

#include "slssteam_messages.pb.h"

#include <cstddef>
#include <cstdint>

enum EMsgType : uint16_t
{
	EMSG_SERVICE_METHOD_RESPONSE = 147,            //k_EMsgServiceMethodResponse (incoming ServiceMethod reply)
	EMSG_SERVICE_METHOD_CALL_FROM_CLIENT = 151,    //k_EMsgServiceMethodCallFromClient (outgoing ServiceMethod call)
	EMSG_GAMESPLAYED_NO_DATABLOB = 715,
	EMSG_GAMESPLAYED = 742,
	EMSG_REQUEST_USERSTATS = 818,                  //k_EMsgClientGetUserStats (outgoing client stats request)
	EMSG_REQUEST_USERSTATS_RESPONSE = 819,         //k_EMsgClientGetUserStatsResponse (incoming client stats response)
	EMSG_APPOWNERSHIPTICKET_REQUEST = 857,       //k_EMsgClientGetAppOwnershipTicket (outgoing raw-frame drop)
	EMSG_APPOWNERSHIPTICKET_RESPONSE = 858,      //k_EMsgClientGetAppOwnershipTicketResponse (incoming cache save)
	EMSG_ENCRYPTED_APPTICKET_RESPONSE = 5527,
	EMSG_WALLET_INFO_UPDATE = 5528,
	EMSG_GAMESPLAYED_WITH_DATABLOB = 5410,
	EMSG_EMAIL_ADDRESS_INFO = 5456,
	EMSG_PICS_PRODUCTINFO_REQUEST = 8903,
	EMSG_PICS_ACCESSTOKEN_RESPONSE = 8906,
};

enum EGameFlags
{
	//1 << 0 is set for spacewar, not other mp games. idk
	EGAMEFLAG_JOINABLE = 1 << 1, //Or in Server, etc
	EGAMEFLAG_MULTIPLAYER = 1 << 13,
};

class CProtoBufMsgBase
{
public:
	char __pad_0x0[0x1C];		//0x0
	uint16_t type;				//0x1C
	char __pad_0x1E[0x6];		//0x1E
	CMsgProtoBufHeader* header; //0x24
	void* __pBody;				//0x28
	char __pad_0x2C[0x8];		//0x2C

	uint32_t send();
	template<typename T> constexpr T* getBody() const
	{
		return reinterpret_cast<T*>(__pBody);
	}
}; //0x34

// Steam client 2026.10.14 grew the base by 8 bytes (Send reads the header
// from +0x24 and the body from +0x28, previously +0x1C/+0x20).
static_assert(offsetof(CProtoBufMsgBase, type) == 0x1C, "CProtoBufMsgBase::type offset");
static_assert(offsetof(CProtoBufMsgBase, header) == 0x24, "CProtoBufMsgBase::header offset");
static_assert(offsetof(CProtoBufMsgBase, __pBody) == 0x28, "CProtoBufMsgBase::__pBody offset");
static_assert(sizeof(CProtoBufMsgBase) == 0x34, "CProtoBufMsgBase size");


//Replaced by actual dumped & protoc generated classes
//TODO: Replace ticket.cpp implementation with proper class too
class CMsgAppOwnershipTicketResponse
{
public:
	char __pad_0x0[0x10];	//0x0
	//Ticket gets accessed like this: pTicket = *(int *)(*(uint *)(local_48.pBody_likely + 0x10) & 0xfffffffe);
	void** ppTicket;			//0x10
	uint32_t appId;			//0x14
	uint32_t result;		//0x18
}; //0x1C ?
