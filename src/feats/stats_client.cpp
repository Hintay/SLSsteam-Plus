#include "stats_client.hpp"

#include "../config.hpp"
#include "../curl.hpp"
#include "../log.hpp"

#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace StatsClient
{
	namespace
	{
		std::mutex g_mutex;
		std::unordered_map<uint32_t, uint64_t> g_cache;

		bool parseSteamId(const std::string& body, uint64_t* out)
		{
			if (body.empty()) return false;
			char* end = nullptr;
			const unsigned long long val = strtoull(body.c_str(), &end, 10);
			if (end == body.c_str() || val == 0) return false;
			*out = static_cast<uint64_t>(val);
			return true;
		}

		struct FetchResult {
			bool ok = false;
			uint64_t steamId = 0;
		};

		// Run the HTTP request on a real thread so the caller (which may be on
		// a Steam coroutine with a tiny stack) is not at risk of stack overflow
		// from curl + OpenSSL init.
		FetchResult doFetchOnWorker(uint32_t appId)
		{
			FetchResult result;
			std::mutex mtx;
			std::condition_variable cv;
			bool done = false;

			std::thread([&] {
				char url[128];
				std::snprintf(url, sizeof(url), "https://stats.opensteamtool.com/%u", appId);

				std::string body;
				long status = 0;
				const std::vector<std::pair<std::string,std::string>> headers = {
					{"User-Agent", "OpenSteamTool/1.0"}
				};
				const int rc = Curl::request("GET", url, headers, {}, body, status);

				{
					std::lock_guard<std::mutex> lock(mtx);
					if (rc == 0 && status == 200)
						result.ok = parseSteamId(body, &result.steamId);
					if (!result.ok && rc != 0)
						g_pLog->debug("StatsClient: fetch failed appid=%u status=%ld curl=%d\n",
						              appId, status, rc);
					else if (!result.ok)
						g_pLog->debug("StatsClient: invalid response appid=%u status=%ld body_len=%zu\n",
						              appId, status, body.size());
					done = true;
				}
				cv.notify_one();
			}).detach();

			std::unique_lock<std::mutex> lock(mtx);
			cv.wait(lock, [&] { return done; });
			return result;
		}
	}

	bool fetchStatSteamId(uint32_t appId, uint64_t* outSteamId)
	{
		if (!outSteamId || appId == 0) return false;

		if (!g_config.statsEnableApi.get())
		{
			g_pLog->debug("StatsClient: API disabled, skipping appid=%u\n", appId);
			return false;
		}

		{
			std::lock_guard<std::mutex> lock(g_mutex);
			const auto it = g_cache.find(appId);
			if (it != g_cache.end())
			{
				*outSteamId = it->second;
				return true;
			}
		}

		const auto result = doFetchOnWorker(appId);

		if (!result.ok) return false;

		{
			std::lock_guard<std::mutex> lock(g_mutex);
			g_cache[appId] = result.steamId;
		}

		*outSteamId = result.steamId;
		g_pLog->info("StatsClient: resolved appid=%u steamid=%llu\n",
		             appId, static_cast<unsigned long long>(result.steamId));
		return true;
	}
}
