#include "curl.hpp"

#include "log.hpp"

#include <algorithm>
#include <curl/curl.h>
#include <curl/easy.h>
#include <limits>
#include <mutex>
#include <strings.h>  // strcasecmp (POSIX)

namespace
{
	std::once_flag s_curlInitOnce;
	std::mutex s_reusableHandleMutex;
	CURL* s_reusableHandle = nullptr;

	void ensureCurlGlobalInit()
	{
		// curl_easy_init lazily runs the non-thread-safe curl_global_init on first
		// use; force it once up-front so concurrent RequestCode fetch threads cannot
		// race that global initialisation.
		std::call_once(s_curlInitOnce, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
	}

	uint32_t clampTimeoutMs(uint32_t value, uint32_t defVal)
	{
		return value == 0 ? defVal : value;
	}

	long clampCurlTimeoutMs(uint64_t value)
	{
		const uint64_t maxLong = static_cast<uint64_t>(std::numeric_limits<long>::max());
		return static_cast<long>(std::min(value, maxLong));
	}

	long connectTimeoutMs(const Curl::RequestOptions& options)
	{
		const uint64_t connectMs = clampTimeoutMs(options.timeoutConnectMs, Curl::RequestOptions().timeoutConnectMs);
		return std::max(1L, clampCurlTimeoutMs(connectMs));
	}

	long totalTimeoutMs(const Curl::RequestOptions& options)
	{
		const uint64_t totalMs = clampTimeoutMs(options.timeoutTotalMs, Curl::RequestOptions().timeoutTotalMs);
		return std::max(1L, clampCurlTimeoutMs(totalMs));
	}
}

// Accumulate response bytes into a std::string.
static size_t writeCallback(const char* content, size_t size, size_t memberSize, std::string* data)
{
	data->append(content, size * memberSize);
	return size * memberSize;
}

int Curl::request(const char* method,
                  const char* url,
                  const std::vector<std::pair<std::string, std::string>>& headers,
                  const std::string& body,
                  std::string& out,
                  long& statusOut)
{
	return Curl::request(method, url, headers, body, out, statusOut, RequestOptions());
}

int Curl::request(const char* method,
                  const char* url,
                  const std::vector<std::pair<std::string, std::string>>& headers,
                  const std::string& body,
                  std::string& out,
                  long& statusOut,
                  const RequestOptions& options)
{
	statusOut = 0;

	ensureCurlGlobalInit();

	std::unique_lock<std::mutex> reuseLock;
	CURL* handle = nullptr;
	if (options.reuseConnection)
	{
		reuseLock = std::unique_lock<std::mutex>(s_reusableHandleMutex);
		if (!s_reusableHandle)
			s_reusableHandle = curl_easy_init();
		handle = s_reusableHandle;
	}
	else
	{
		handle = curl_easy_init();
	}
	if (!handle)
		return CURLE_FAILED_INIT;

	curl_easy_reset(handle);

	curl_easy_setopt(handle, CURLOPT_URL, url);
	curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, writeCallback);
	curl_easy_setopt(handle, CURLOPT_WRITEDATA, &out);

	// Follow redirects.
	curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);

	// Optionally forbid a redirect from downgrading to a non-https scheme.
	if (options.httpsOnlyRedirects)
	{
#if defined(CURLOPT_REDIR_PROTOCOLS_STR)
		curl_easy_setopt(handle, CURLOPT_REDIR_PROTOCOLS_STR, "https");
#else
		curl_easy_setopt(handle, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
#endif
	}

	// Method / body setup.
	const bool isPost = (method != nullptr && strcasecmp(method, "POST") == 0);
	if (isPost) {
		curl_easy_setopt(handle, CURLOPT_POST, 1L);
		curl_easy_setopt(handle, CURLOPT_POSTFIELDS, body.c_str());
		curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
	} else if (method != nullptr && strcasecmp(method, "GET") != 0) {
		// Support HEAD, PUT, DELETE, … if ever needed.
		curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, method);
	}

	// Build curl_slist for extra headers.
	struct curl_slist* slist = nullptr;
	for (const auto& [k, v] : headers) {
		std::string header = k + ": " + v;
		slist = curl_slist_append(slist, header.c_str());
	}
	if (slist)
		curl_easy_setopt(handle, CURLOPT_HTTPHEADER, slist);

	curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, connectTimeoutMs(options));
	curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, totalTimeoutMs(options));
	curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(handle, CURLOPT_FRESH_CONNECT, options.reuseConnection ? 0L : 1L);
	curl_easy_setopt(handle, CURLOPT_FORBID_REUSE, options.reuseConnection ? 0L : 1L);

	CURLcode res = curl_easy_perform(handle);

	if (res == CURLE_OK)
		curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &statusOut);

	if (slist)
		curl_slist_free_all(slist);

	if (!options.reuseConnection)
		curl_easy_cleanup(handle);
	else if (res != CURLE_OK)
	{
		// Drop the cached easy handle on transport/TLS failures so the next request
		// rebuilds DNS/TCP/TLS state, closing the connection on transport error.
		curl_easy_cleanup(s_reusableHandle);
		s_reusableHandle = nullptr;
	}
	return static_cast<int>(res);
}

int Curl::getString(const char* url, std::string& out)
{
	long status = 0;
	static const std::vector<std::pair<std::string, std::string>> noHeaders;
	static const std::string noBody;
	return Curl::request("GET", url, noHeaders, noBody, out, status);
}
