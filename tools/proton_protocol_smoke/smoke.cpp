#include "../../src/feats/protoninject_protocol.h"

#include <cassert>
#include <cstring>

int main()
{
	assert(std::strcmp(SLS_PROTON_INJECT_SESSION_ENV, "PROTON_SLS_INJECT_SESSION") == 0);
	assert(std::strcmp(SLS_PROTON_INJECT_SOCKET_PREFIX, "sls_proton_inject_") == 0);
	assert(std::strcmp(SLS_PROTON_INJECT_PROTO_MAGIC, "SLSPI/1") == 0);

	assert(sls_proton_select_app_id("480", "111", "222") == 480);
	assert(sls_proton_select_app_id(nullptr, "111", "222") == 111);
	assert(sls_proton_select_app_id("", nullptr, "222") == 222);
	assert(sls_proton_select_app_id("bad", "also-bad", nullptr) == 0);

	char socketName[128] = {};
	assert(sls_proton_build_socket_name(socketName, sizeof(socketName), "abc123") == 1);
	assert(std::strcmp(socketName, "sls_proton_inject_abc123") == 0);
	assert(sls_proton_build_socket_name(socketName, 8, "abc123") == 0);

	char okResponse[512] = {};
	assert(sls_proton_build_ok_response(okResponse, sizeof(okResponse), 480, "/tmp/OnlineFix.dll") == 1);
	assert(std::strcmp(okResponse, "SLSPI/1 OK 480 /tmp/OnlineFix.dll\n") == 0);

	uint32_t parsedAppId = 0;
	char parsedDll[256] = {};
	assert(sls_proton_parse_ok_response(okResponse, &parsedAppId, parsedDll, sizeof(parsedDll)) == 1);
	assert(parsedAppId == 480);
	assert(std::strcmp(parsedDll, "/tmp/OnlineFix.dll") == 0);
	assert(sls_proton_parse_ok_response("SLSPI/1 DENY unknown\n", &parsedAppId, parsedDll, sizeof(parsedDll)) == 0);

	return 0;
}
