#pragma once

#include <cstdint>

struct CNetPacket;

namespace Achievements
{
	// Raw outgoing hook (from hkCWebSocketConnection_BBuildAndAsyncSendFrame). For a
	// Player.GetUserStats#1 ServiceMethod call (EMsg 151) or a legacy
	// CMsgClientGetUserStats (EMsg 818) of a redirected app, rewrite the donor
	// steamid into the request and (151) track jobid_source -> appId. Schema probes
	// (requests with sha_schema) are converted to full fetches by stripping
	// sha_schema so the server always returns the latest schema. If the frame must
	// be re-sent modified, returns true and points outData/outSize at a thread-local
	// replacement packet; the caller sends that instead. Returns false when
	// achievements does not handle the frame.
	//
	// The ServiceMethod (151) path provably does NOT traverse CProtoBufMsgBase::Send
	// on modern Steam, so it MUST be intercepted here at the raw packet layer (same
	// reason requestcode moved here). The stats CAPIJob fallback stays a no-op.
	bool onSendFrame(const uint8_t* pubData, uint32_t cubData,
	                 const uint8_t*& outData, uint32_t& outSize);

	// Called from hkCCMConnection_RecvPkt. In offline schema mode, delivers
	// fabricated NO_CONNECTION responses for dropped 151 requests so the CAPIJob
	// completes immediately instead of waiting for a timeout.
	bool nextInjection(const uint8_t*& outData, uint32_t& outSize);

	// Raw incoming hook (from hkCCMConnection_RecvPkt). For a matching
	// Player.GetUserStats#1 response (EMsg 147, jobid_target pending) or a legacy
	// CMsgClientGetUserStatsResponse (EMsg 819) of a redirected app, clear the stat
	// values and force eresult = OK so Steam keeps the schema but falls back to its
	// local achievement cache. Rewrites pkt->m_pubData / m_cubData in place.
	void onRecvPacket(CNetPacket* pkt);

	// Called from hkCAPIJob_GetPlayerStats. In offline schema mode, forces
	// eresult to NO_CONNECTION so Steam falls back to local cache (bin files).
	// In online mode (default), no-op — the raw network hooks handle everything.
	void getPlayerStats(uint32_t& eresult);
}
