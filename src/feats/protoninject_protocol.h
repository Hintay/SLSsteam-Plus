#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SLS_PROTON_INJECT_SESSION_ENV "PROTON_SLS_INJECT_SESSION"
#define SLS_PROTON_INJECT_SOCKET_PREFIX "sls_proton_inject_"
#define SLS_PROTON_INJECT_CONTROL_TOKEN "control"
#define SLS_PROTON_INJECT_PROTO_MAGIC "SLSPI/1"

static inline uint32_t sls_proton_parse_app_id(const char *value)
{
	if (!value || !*value) return 0;
	uint32_t result = 0;
	for (const char *p = value; *p; ++p) {
		if (*p < '0' || *p > '9') return 0;
		const uint32_t digit = (uint32_t)(*p - '0');
		if (result > (UINT32_MAX - digit) / 10U) return 0;
		result = result * 10U + digit;
	}
	return result;
}

static inline uint32_t sls_proton_select_app_id(const char *explicit_app_id,
														const char *steam_app_id,
														const char *steam_game_id)
{
	uint32_t app_id = sls_proton_parse_app_id(explicit_app_id);
	if (app_id) return app_id;
	app_id = sls_proton_parse_app_id(steam_app_id);
	if (app_id) return app_id;
	return sls_proton_parse_app_id(steam_game_id);
}

static inline int sls_proton_build_decimal(char *out, size_t out_size, uint32_t value)
{
	if (!out || out_size == 0) return 0;
	const int written = snprintf(out, out_size, "%u", value);
	if (written < 0 || (size_t)written >= out_size) {
		out[0] = '\0';
		return 0;
	}
	return 1;
}

static inline int sls_proton_build_socket_name(char *out, size_t out_size, const char *token)
{
	if (!out || out_size == 0 || !token || !*token) return 0;
	const int written = snprintf(out, out_size, "%s%s", SLS_PROTON_INJECT_SOCKET_PREFIX, token);
	if (written < 0 || (size_t)written >= out_size) {
		out[0] = '\0';
		return 0;
	}
	return 1;
}

static inline int sls_proton_build_ok_response(char *out, size_t out_size, uint32_t app_id, const char *dll_path)
{
	if (!out || out_size == 0 || app_id == 0 || !dll_path || dll_path[0] != '/') return 0;
	for (const char *p = dll_path; *p; ++p) {
		if (*p == '\n' || *p == '\r') return 0;
	}
	const int written = snprintf(out, out_size, "%s OK %u %s\n", SLS_PROTON_INJECT_PROTO_MAGIC, app_id, dll_path);
	if (written < 0 || (size_t)written >= out_size) {
		out[0] = '\0';
		return 0;
	}
	return 1;
}

static inline int sls_proton_parse_ok_response(const char *line, uint32_t *app_id, char *dll_path, size_t dll_path_size)
{
	if (!line || !app_id || !dll_path || dll_path_size == 0) return 0;
	const char prefix[] = SLS_PROTON_INJECT_PROTO_MAGIC " OK ";
	const size_t prefix_len = sizeof(prefix) - 1;
	if (strncmp(line, prefix, prefix_len) != 0) return 0;

	const char *app_start = line + prefix_len;
	const char *space = strchr(app_start, ' ');
	if (!space || space == app_start) return 0;

	char app_buf[16];
	const size_t app_len = (size_t)(space - app_start);
	if (app_len >= sizeof(app_buf)) return 0;
	for (size_t i = 0; i < app_len; ++i) app_buf[i] = app_start[i];
	app_buf[app_len] = '\0';

	uint32_t parsed_app = sls_proton_parse_app_id(app_buf);
	if (!parsed_app) return 0;

	const char *path_start = space + 1;
	if (path_start[0] != '/') return 0;
	const char *path_end = path_start;
	while (*path_end && *path_end != '\n' && *path_end != '\r') ++path_end;
	const size_t path_len = (size_t)(path_end - path_start);
	if (path_len == 0 || path_len >= dll_path_size) return 0;

	for (size_t i = 0; i < path_len; ++i) dll_path[i] = path_start[i];
	dll_path[path_len] = '\0';
	*app_id = parsed_app;
	return 1;
}

#ifdef __cplusplus
}
#endif
