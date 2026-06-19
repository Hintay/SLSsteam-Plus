#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>


namespace Curl
{
	struct RequestOptions
	{
		uint32_t timeoutConnectMs = 5000;
		uint32_t timeoutTotalMs = 10000;
		bool reuseConnection = false;
		// Restrict HTTP redirects to https only (the initial URL protocol is
		// unaffected). Use for fetches whose response decides hook targets so a
		// 30x cannot downgrade to cleartext. Off by default to not break http
		// manifest providers that legitimately redirect.
		bool httpsOnlyRedirects = false;
	};

	// Simple GET — kept for backward compatibility; delegates to request().
	// Returns CURLE_OK (0) on success; body appended to out.
	int getString(const char* url, std::string& out);

	// General HTTP request.
	// method    : "GET", "POST", …
	// headers   : optional extra request headers sent via curl_slist
	// body      : request body (used for POST; ignored for GET when empty)
	// out       : response body accumulated via the write callback
	// statusOut : HTTP status code (e.g. 200); set to 0 on transport error
	// Returns   : CURLcode (0 = CURLE_OK; non-zero = transport/TLS error)
	int request(const char* method,
	            const char* url,
	            const std::vector<std::pair<std::string, std::string>>& headers,
	            const std::string& body,
	            std::string& out,
	            long& statusOut);

	int request(const char* method,
	            const char* url,
	            const std::vector<std::pair<std::string, std::string>>& headers,
	            const std::string& body,
	            std::string& out,
	            long& statusOut,
	            const RequestOptions& options);
}
