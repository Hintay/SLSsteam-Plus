#include "achievements.hpp"

#include "apps.hpp"

#include "../config.hpp"
#include "../sdk/CProtoBufMsgBase.hpp"   // EMsgType enum + CMsgProtoBufHeader
#include "../sdk/EResult.hpp"
#include "../sdk/RawNetPacket.hpp"
#include "slssteam_messages.pb.h"

#include "../lua/LuaLoader.hpp"
#include "../log.hpp"

#include <atomic>
#include <chrono>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// User-stats interception at the raw packet layer. Steam fetches achievement/stat
// data via two paths:
//   1. ServiceMethod (EMsg 151/147): Player.GetUserStats#1
//   2. Legacy client message (EMsg 818/819): CMsgClientGetUserStats
//
// The ServiceMethod (151/147) path does NOT traverse CProtoBufMsgBase::Send/
// InitFromPacket on modern Steam (outgoing 151 never reached that hook), so
// achievements is intercepted here at the raw layer:
//   outgoing CWebSocketConnection::BBuildAndAsyncSendFrame
//   incoming CCMConnection::RecvPkt(CNetPacket*)
//
// For added (lua/config) apps that are not genuinely owned, the outgoing query's
// steamid is rewritten to a donor so the server returns a valid schema; incoming
// stat values are then cleared so Steam keeps the schema but falls back to local
// cache. Schema probes (requests with sha_schema) are converted to full fetches
// by stripping sha_schema — RE of CAPIJobRequestUserStats confirmed the response
// handler is response-driven and does not track the request type. This ensures
// schema updates (e.g. new achievements) are picked up even though the real user
// does not own the game. Redirect only controlled apps that have not been
// confirmed genuinely owned by Steam's original ownership path.

namespace Achievements
{
	namespace
	{
		constexpr char TARGET_JOB_NAME[] = "Player.GetUserStats#1";

		constexpr auto kLegacyPendingTtl = std::chrono::seconds(60);

		struct LegacyPending {
			size_t count = 0;
			std::chrono::steady_clock::time_point lastTouched;
		};

		// Fabricated NO_CONNECTION response for offline schema mode (151 path).
		struct OfflineInjection {
			uint32_t appId = 0;
			std::vector<uint8_t> packet;
		};

		// jobid_source (outgoing 151) -> appId for online donor redirect.
		// Touched from the send hook and the recv hook; guard with g_mutex.
		// The atomics are lock-free fast-path gates for the recv hook (runs on
		// every incoming packet); only written under g_mutex.
		std::unordered_map<uint64_t, uint32_t> g_pending;
		std::unordered_map<uint32_t, LegacyPending> g_legacyPending;
		std::deque<OfflineInjection> g_offlineQueue;
		std::mutex          g_mutex;
		std::atomic<size_t> g_pendingCount{0};
		std::atomic<size_t> g_legacyPendingCount{0};
		std::atomic<size_t> g_offlineQueueCount{0};

		// Holds the injected packet bytes so the pointer returned by nextInjection
		// remains valid until RecvPkt consumes it.
		thread_local std::vector<uint8_t> t_injectBuf;

		// Controlled app, unless the original ownership path proved it is genuinely owned.
		inline bool shouldRedirectStats(uint32_t appId)
		{
			return Apps::shouldTreatAsFakeOwned(appId);
		}

		void publishCountsLocked()
		{
			g_pendingCount.store(g_pending.size(), std::memory_order_release);
			size_t legacyTotal = 0;
			for (const auto& it : g_legacyPending)
			{
				legacyTotal += it.second.count;
			}
			g_legacyPendingCount.store(legacyTotal, std::memory_order_release);
		}

		bool queueOfflineResponse(uint32_t appId, uint64_t jobId, CMsgProtoBufHeader hdr)
		{
			hdr.set_jobid_target(jobId);
			hdr.clear_jobid_source();
			hdr.set_eresult(ERESULT_NO_CONNECTION);

			CPlayer_GetUserStats_Response resp;
			std::string newHdr, newBody;
			if (!hdr.SerializeToString(&newHdr) || !resp.SerializeToString(&newBody)) return false;

			OfflineInjection inj;
			inj.appId = appId;
			const uint8_t* out = nullptr;
			uint32_t outSz = 0;
			if (!netpacket::AssembleRaw(inj.packet,
			                           static_cast<uint32_t>(EMSG_SERVICE_METHOD_RESPONSE) | kMsgHdrProtoFlag,
			                           newHdr.data(), newHdr.size(), newBody.data(), newBody.size(),
			                           out, outSz))
				return false;

			std::lock_guard<std::mutex> lock(g_mutex);
			g_offlineQueue.push_back(std::move(inj));
			g_offlineQueueCount.store(g_offlineQueue.size(), std::memory_order_release);
			return true;
		}

		void purgeExpiredLegacyLocked(std::chrono::steady_clock::time_point now)
		{
			for (auto it = g_legacyPending.begin(); it != g_legacyPending.end();)
			{
				if (now - it->second.lastTouched > kLegacyPendingTtl)
					it = g_legacyPending.erase(it);
				else
					++it;
			}
		}

		void addServicePending(uint64_t jobId, uint32_t appId)
		{
			std::lock_guard<std::mutex> lock(g_mutex);
			g_pending[jobId] = appId;
			publishCountsLocked();
		}

		bool peekServicePending(uint64_t jobId, uint32_t& appId)
		{
			std::lock_guard<std::mutex> lock(g_mutex);
			const auto it = g_pending.find(jobId);
			if (it == g_pending.end()) return false;
			appId = it->second;
			return true;
		}

		bool consumeServicePending(uint64_t jobId)
		{
			std::lock_guard<std::mutex> lock(g_mutex);
			const auto erased = g_pending.erase(jobId);
			if (!erased) return false;
			publishCountsLocked();
			return true;
		}

		void addLegacyPending(uint32_t appId)
		{
			std::lock_guard<std::mutex> lock(g_mutex);
			const auto now = std::chrono::steady_clock::now();
			purgeExpiredLegacyLocked(now);
			auto& pending = g_legacyPending[appId];
			pending.count++;
			pending.lastTouched = now;
			publishCountsLocked();
		}

		bool hasLegacyPending(uint32_t appId)
		{
			std::lock_guard<std::mutex> lock(g_mutex);
			const auto now = std::chrono::steady_clock::now();
			purgeExpiredLegacyLocked(now);
			publishCountsLocked();
			const auto it = g_legacyPending.find(appId);
			return it != g_legacyPending.end() && it->second.count > 0;
		}

		bool consumeLegacyPending(uint32_t appId)
		{
			std::lock_guard<std::mutex> lock(g_mutex);
			const auto now = std::chrono::steady_clock::now();
			purgeExpiredLegacyLocked(now);
			const auto it = g_legacyPending.find(appId);
			if (it == g_legacyPending.end() || it->second.count == 0)
			{
				publishCountsLocked();
				return false;
			}
			it->second.count--;
			if (it->second.count == 0)
				g_legacyPending.erase(it);
			else
				it->second.lastTouched = now;
			publishCountsLocked();
			return true;
		}

	}

	bool onSendFrame(const uint8_t* pubData, uint32_t cubData,
	                 const uint8_t*& outData, uint32_t& outSize)
	{
		uint16_t eMsg = 0;
		const uint8_t *pHdr = nullptr, *pBody = nullptr;
		uint32_t cbHdr = 0, cbBody = 0;
		if (!netpacket::UnpackRaw(pubData, cubData, eMsg, pHdr, cbHdr, pBody, cbBody)) return false;

		// ── Path 1: ServiceMethod Player.GetUserStats#1 (EMsg 151) ────────────
		if (eMsg == EMSG_SERVICE_METHOD_CALL_FROM_CLIENT)
		{
			CMsgProtoBufHeader hdr;
			if (!hdr.ParseFromArray(pHdr, static_cast<int>(cbHdr))) return false;
			if (!hdr.has_target_job_name() || hdr.target_job_name() != TARGET_JOB_NAME) return false;

			CPlayer_GetUserStats_Request req;
			if (!req.ParseFromArray(pBody, static_cast<int>(cbBody))) return false;
			if (!req.has_appid()) return false;

			const uint32_t appId = req.appid();
			if (!shouldRedirectStats(appId)) return false;
			if (g_config.offlineAchievementsSchema.get())
			{
				if (!hdr.has_jobid_source()) return false;
				if (!queueOfflineResponse(appId, hdr.jobid_source(), hdr))
				{
					g_pLog->warn("Achievements: failed to queue offline 151 response app=%u\n", appId);
					return false;
				}
				outData = nullptr;
				outSize = 0;
				g_pLog->debug("Achievements: raw 151 app=%u offline — dropped, injecting NO_CONNECTION\n", appId);
				return true;
			}
			if (!hdr.has_jobid_source()) return false;

			const bool isProbe = req.has_sha_schema();
			if (isProbe)
			{
				// Strip sha_schema to turn the probe into a full fetch.
				// RE confirmed: CAPIJobRequestUserStats is response-driven — it
				// checks response.has_schema(), not what the request contained.
				// The server will return the complete schema for the donor, and
				// onRecvPacket clears the donor's stat values as usual.
				req.clear_sha_schema();
			}

			const uint64_t jobId = hdr.jobid_source();
			const uint64_t donor = LuaLoader::getStatSteamId(appId);
			req.set_steamid(donor);

			std::string newBody;
			if (!req.SerializeToString(&newBody)) return false;
			const std::string keepHdr(reinterpret_cast<const char*>(pHdr), cbHdr); // header unchanged

			const bool ok = netpacket::ReplaceSendPacket(pubData, cubData,
			                                            keepHdr.data(), keepHdr.size(),
			                                            newBody.data(), newBody.size(),
			                                            outData, outSize);
			if (!ok)
			{
				g_pLog->warn("Achievements: failed to assemble raw 151 redirect app=%u (jobid=%llu)\n",
				             appId, static_cast<unsigned long long>(jobId));
				return false;
			}

			addServicePending(jobId, appId);
			g_pLog->debug("Achievements: raw 151 %s app=%u using donor steamid (jobid=%llu)\n",
			              isProbe ? "probe->full" : "redirect",
			              appId, static_cast<unsigned long long>(jobId));
			return true;
		}

		// ── Path 2: Legacy CMsgClientGetUserStats (EMsg 818) ──────────────────
		if (eMsg == EMSG_REQUEST_USERSTATS)
		{
			CMsgClientGetUserStats req;
			if (!req.ParseFromArray(pBody, static_cast<int>(cbBody))) return false;
			if (!req.has_game_id()) return false;
			// schema_local_version == -1 signals an initial live-stats fetch.
			if (!req.has_schema_local_version() || req.schema_local_version() != -1) return false;

			const uint32_t appId = static_cast<uint32_t>(req.game_id());
			if (!shouldRedirectStats(appId)) return false;
			if (g_config.offlineAchievementsSchema.get())
			{
				outData = nullptr;
				outSize = 0;
				return true;
			}

			const uint64_t donor = LuaLoader::getStatSteamId(appId);
			req.set_steam_id_for_user(donor);

			std::string newBody;
			if (!req.SerializeToString(&newBody)) return false;
			const std::string keepHdr(reinterpret_cast<const char*>(pHdr), cbHdr);

			const bool ok = netpacket::ReplaceSendPacket(pubData, cubData,
			                                            keepHdr.data(), keepHdr.size(),
			                                            newBody.data(), newBody.size(),
			                                            outData, outSize);
			if (!ok)
			{
				g_pLog->warn("Achievements: failed to assemble raw 818 redirect app=%u\n", appId);
				return false;
			}

			addLegacyPending(appId);
			g_pLog->debug("Achievements: raw 818 redirect app=%u using donor steamid\n", appId);
			return true;
		}

		return false;
	}

	bool nextInjection(const uint8_t*& outData, uint32_t& outSize)
	{
		if (g_offlineQueueCount.load(std::memory_order_acquire) == 0) return false;

		OfflineInjection inj;
		{
			std::lock_guard<std::mutex> lock(g_mutex);
			if (g_offlineQueue.empty()) return false;
			inj = std::move(g_offlineQueue.front());
			g_offlineQueue.pop_front();
			g_offlineQueueCount.store(g_offlineQueue.size(), std::memory_order_release);
		}

		t_injectBuf = std::move(inj.packet);
		outData = t_injectBuf.data();
		outSize = static_cast<uint32_t>(t_injectBuf.size());
		g_pLog->debug("Achievements: injected offline NO_CONNECTION for app=%u\n", inj.appId);
		return outData && outSize;
	}

	void onRecvPacket(CNetPacket* pkt)
	{
		if (!pkt) return;
		uint16_t eMsg = 0;
		const uint8_t *pHdr = nullptr, *pBody = nullptr;
		uint32_t cbHdr = 0, cbBody = 0;
		if (!netpacket::UnpackRaw(pkt->m_pubData, pkt->m_cubData, eMsg, pHdr, cbHdr, pBody, cbBody)) return;

		// ── Path 1: ServiceMethod response (EMsg 147) ─────────────────────────
		if (eMsg == EMSG_SERVICE_METHOD_RESPONSE)
		{
			if (g_pendingCount.load(std::memory_order_acquire) == 0) return; // fast path

			CMsgProtoBufHeader hdr;
			if (!hdr.ParseFromArray(pHdr, static_cast<int>(cbHdr)) || !hdr.has_jobid_target()) return;
			const uint64_t jobId = hdr.jobid_target();

			uint32_t appId = 0;
			if (!peekServicePending(jobId, appId)) return;   // not one of ours

			CPlayer_GetUserStats_Response resp;
			if (!resp.ParseFromArray(pBody, static_cast<int>(cbBody)))
			{
				g_pLog->warn("Achievements: failed to parse raw 147 response app=%u (jobid=%llu)\n",
				             appId, static_cast<unsigned long long>(jobId));
				return;
			}
			resp.clear_stats();                 // keep schema, drop the donor's stat values
			hdr.set_eresult(ERESULT_OK);

			std::string newHdr, newBody;
			if (!hdr.SerializeToString(&newHdr) || !resp.SerializeToString(&newBody))
			{
				g_pLog->warn("Achievements: failed to serialize raw 147 response app=%u (jobid=%llu)\n",
				             appId, static_cast<unsigned long long>(jobId));
				return;
			}

			const uint8_t* replacementData = nullptr;
			uint32_t replacementSize = 0;
			if (!netpacket::BuildRecvPacketReplacement(pkt,
			                                        newHdr.data(), newHdr.size(),
			                                        newBody.data(), newBody.size(),
			                                        replacementData, replacementSize))
			{
				g_pLog->warn("Achievements: failed to assemble raw 147 response app=%u (jobid=%llu)\n",
				             appId, static_cast<unsigned long long>(jobId));
				return;
			}

			if (consumeServicePending(jobId))
			{
				pkt->m_pubData = const_cast<uint8_t*>(replacementData);
				pkt->m_cubData = replacementSize;
				g_pLog->debug("Achievements: raw 147 cleared app=%u (jobid=%llu)\n",
				              appId, static_cast<unsigned long long>(jobId));
			}
			return;
		}

		// ── Path 2: Legacy response CMsgClientGetUserStatsResponse (EMsg 819) ──
		if (eMsg == EMSG_REQUEST_USERSTATS_RESPONSE)
		{
			CMsgClientGetUserStatsResponse resp;
			if (!resp.ParseFromArray(pBody, static_cast<int>(cbBody)) || !resp.has_game_id()) return;
			const uint32_t appId = static_cast<uint32_t>(resp.game_id());
			if (!shouldRedirectStats(appId)) return;

			// Legacy 818/819 does not reliably give us a raw-layer outgoing request to
			// correlate with. Use pending when we saw the 818, but preserve the old
			// working fallback of clearing redirected apps by response appid alone.
			const bool matchedPending = g_legacyPendingCount.load(std::memory_order_acquire) != 0
			                         && hasLegacyPending(appId);

			resp.clear_stats();
			resp.clear_achievement_blocks();
			resp.set_eresult(ERESULT_OK);

			std::string newBody;
			if (!resp.SerializeToString(&newBody))
			{
				g_pLog->warn("Achievements: failed to serialize raw 819 response app=%u\n", appId);
				return;
			}
			const std::string keepHdr(reinterpret_cast<const char*>(pHdr), cbHdr);

			if (!netpacket::ReplaceRecvPacket(pkt,
			                                 keepHdr.data(), keepHdr.size(),
			                                 newBody.data(), newBody.size()))
			{
				g_pLog->warn("Achievements: failed to assemble raw 819 response app=%u\n", appId);
				return;
			}

			if (matchedPending) consumeLegacyPending(appId);
			g_pLog->debug("Achievements: raw 819 cleared app=%u%s\n",
			              appId, matchedPending ? "" : " (fallback)");
			return;
		}
	}

	void getPlayerStats(uint32_t& eresult)
	{
		if (!g_config.offlineAchievementsSchema.get()) return;
		if (eresult == ERESULT_OK) return;
		eresult = ERESULT_NO_CONNECTION;
	}
}
