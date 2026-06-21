#include "LuaLoader.hpp"

#include "../config.hpp"
#include "../curl.hpp"
#include "../feats/stats_client.hpp"
#include "../globals.hpp"
#include "../log.hpp"
#include "ManifestProvider.hpp"
#include "../filewatcher.hpp"

// Use the raw Lua C API.
// Do NOT use sol2 or any wrapper.
extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/inotify.h>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace LuaLoader {

    // ── Module state tables (definitions) ─────────────────────────────────
    std::unordered_map<uint32_t, std::vector<uint8_t>> depotKeys;
    std::unordered_map<uint32_t, ManifestOverride>      manifestOverrides;
    std::unordered_set<uint32_t>                        ownedAppIds;
    std::unordered_map<uint32_t, uint64_t>              appTokens;
    std::unordered_map<uint32_t, uint64_t>              statSteamIds;
    std::unordered_map<uint32_t, LuaTicket>             appTickets;
    std::unordered_map<uint32_t, LuaTicket>             encTickets;

    // ── Per-file lifecycle tracking ───────────────────────────────────────
    // All guarded by g_fileMtx and mutated only while g_luaMtx is held. Each
    // lua file records its own contribution, then rebuildGlobalState() folds the
    // files in scan priority order into the public tables above. This avoids
    // stale manifest/token/stat/ticket data when a file is edited, deleted, or
    // loses a field while another file still references the same id.
    struct FileContribution {
        uint32_t mtime = 0;
        std::unordered_set<uint32_t> ownedIds;
        std::unordered_map<uint32_t, std::vector<uint8_t>> depotKeys;
        std::unordered_map<uint32_t, ManifestOverride> manifestOverrides;
        std::unordered_map<uint32_t, uint64_t> appTokens;
        std::unordered_map<uint32_t, uint64_t> statSteamIds;
        std::unordered_map<uint32_t, LuaTicket> appTickets;
        std::unordered_map<uint32_t, LuaTicket> encTickets;
        int fetchCodeRef = LUA_NOREF;
        int fetchCodeExRef = LUA_NOREF;
    };

    std::string g_currentFile;
    FileContribution* g_currentContribution = nullptr;
    std::unordered_map<std::string, FileContribution> g_fileContribs;
    std::vector<std::string> g_fileOrder;
    std::unordered_map<uint32_t, uint32_t> g_purchaseTime;
    std::vector<uint32_t> g_pendingAdditions;
    std::vector<uint32_t> g_pendingRemovals;
    std::mutex g_fileMtx;

    // ── Internal state ─────────────────────────────────────────────────────
    static lua_State* g_lua = nullptr;
    // The lua_State is not thread-safe. init() runs single-threaded at startup,
    // but fetchManifestCode runs the lua provider callbacks from std::async
    // workers (one per concurrent depot), so all g_lua access from there is
    // serialized under this mutex.
    //
    // Tradeoff (accepted): if a lua provider callback itself does HTTP (http_get/
    // http_post), that I/O runs while the lock is held, serializing concurrent
    // lua-provider fetches. This is inherent to a single-threaded VM — the lock
    // cannot be released mid-pcall while the script is running. The built-in HTTP
    // provider (no lua) is unaffected. Pathological many-depot + lua-HTTP installs
    // may exceed the recv-side wait and fall back to a failed (retryable) install.
    static std::mutex g_luaMtx;

    // ── Lua-dir hot-reload ─────────────────────────────────────────────────
    // g_luaWatcher watches the scanned lua dirs after init(). g_luaDirs is a
    // process-lifetime store so the const char* paths handed to addDirectory()
    // stay valid. g_onDepotsChanged is an optional notification seam.
    static CFileWatcher* g_luaWatcher = nullptr;
    static std::vector<std::string> g_luaDirs;
    static std::atomic<void (*)()> g_onDepotsChanged{nullptr};

    // Case-insensitive function registry: lowercase name → C function.
    static std::unordered_map<std::string, lua_CFunction> g_func_registry;

    // Lua registry references for callback functions captured via luaL_ref.
    // Initialised to LUA_NOREF (-1) so callers can test before invoking.
    static int g_fetchCodeRef   = LUA_NOREF;
    static int g_fetchCodeExRef = LUA_NOREF;

    // ── Case-insensitive global __index metamethod ─────────────────────────
    // When a Lua script references an unknown global (e.g. AddAppId),
    // we lower-case the name and look it up in g_func_registry so that
    // any capitalisation variant resolves to the registered function.
    static int case_insensitive_index(lua_State* L) {
        const char* name = lua_tostring(L, 2);
        if (!name) {
            lua_pushnil(L);
            return 1;
        }
        std::string lower;
        lower.reserve(std::strlen(name));
        for (const char* p = name; *p; ++p) {
            lower += static_cast<char>(std::tolower(static_cast<unsigned char>(*p)));
        }
        auto it = g_func_registry.find(lower);
        if (it != g_func_registry.end()) {
            lua_pushcfunction(L, it->second);
            return 1;
        }
        lua_pushnil(L);
        return 1;
    }

    // Register fn in _G under lowercase_name AND in g_func_registry so any
    // case variant also resolves via the __index metamethod.
    static void register_func(lua_State* L,
                              const char* lowercase_name,
                              lua_CFunction fn)
    {
        g_func_registry[lowercase_name] = fn;
        lua_pushcfunction(L, fn);
        lua_setglobal(L, lowercase_name);
    }

    // ── Hex helpers ────────────────────────────────────────────────────────

    // Convert a single ASCII hex character to its nibble value.
    // Returns -1 on invalid input.
    static int hexNibble(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    // Parse a 64-character hex string into a 32-byte vector.
    // Returns false (and leaves out unchanged) on malformed input.
    static bool parseHex64(const char* hex, std::vector<uint8_t>& out) {
        if (std::strlen(hex) != 64) return false;
        std::vector<uint8_t> result;
        result.reserve(32);
        for (int i = 0; i < 64; i += 2) {
            int hi = hexNibble(hex[i]);
            int lo = hexNibble(hex[i + 1]);
            if (hi < 0 || lo < 0) return false;
            result.push_back(static_cast<uint8_t>((hi << 4) | lo));
        }
        out = std::move(result);
        return true;
    }

    // Parse a decimal uint64 string (as used by addtoken / setmanifestid).
    // Returns false on empty string, overflow, or non-digit characters.
    static bool parseU64Decimal(const char* str, uint64_t& out) {
        if (!str || *str == '\0') return false;
        errno = 0;
        char* end = nullptr;
        unsigned long long v = strtoull(str, &end, 10);
        if (errno != 0 || end == str || *end != '\0') return false;
        out = static_cast<uint64_t>(v);
        return true;
    }

    static constexpr size_t kMaxLuaTicketBytes = 256 * 1024;

    static void releaseContributionRefs(FileContribution& contrib)
    {
        if (!g_lua) return;
        if (contrib.fetchCodeRef != LUA_NOREF) {
            if (g_fetchCodeRef == contrib.fetchCodeRef) g_fetchCodeRef = LUA_NOREF;
            luaL_unref(g_lua, LUA_REGISTRYINDEX, contrib.fetchCodeRef);
            contrib.fetchCodeRef = LUA_NOREF;
        }
        if (contrib.fetchCodeExRef != LUA_NOREF) {
            if (g_fetchCodeExRef == contrib.fetchCodeExRef) g_fetchCodeExRef = LUA_NOREF;
            luaL_unref(g_lua, LUA_REGISTRYINDEX, contrib.fetchCodeExRef);
            contrib.fetchCodeExRef = LUA_NOREF;
        }
    }

    static size_t fileOrderRank(const std::string& path)
    {
        for (size_t i = 0; i < g_luaDirs.size(); ++i) {
            const std::string& dir = g_luaDirs[i];
            if (path.size() > dir.size() &&
                path.compare(0, dir.size(), dir) == 0 &&
                path[dir.size()] == '/') {
                return i;
            }
        }
        return g_luaDirs.size();
    }

    static void sortFileOrder()
    {
        std::sort(g_fileOrder.begin(), g_fileOrder.end(), [](const std::string& a, const std::string& b) {
            const size_t rankA = fileOrderRank(a);
            const size_t rankB = fileOrderRank(b);
            if (rankA != rankB) return rankA < rankB;
            return a < b;
        });
    }

    static void rememberFileOrder(const std::string& path)
    {
        if (std::find(g_fileOrder.begin(), g_fileOrder.end(), path) == g_fileOrder.end()) {
            g_fileOrder.push_back(path);
        }
        sortFileOrder();
    }

    static void eraseFileOrder(const std::string& path)
    {
        g_fileOrder.erase(std::remove(g_fileOrder.begin(), g_fileOrder.end(), path), g_fileOrder.end());
    }

    static void rebuildGlobalState()
    {
        const std::unordered_set<uint32_t> oldOwned = ownedAppIds;

        depotKeys.clear();
        manifestOverrides.clear();
        ownedAppIds.clear();
        appTokens.clear();
        statSteamIds.clear();
        appTickets.clear();
        encTickets.clear();
        g_purchaseTime.clear();
        g_fetchCodeRef = LUA_NOREF;
        g_fetchCodeExRef = LUA_NOREF;

        for (const auto& path : g_fileOrder) {
            const auto it = g_fileContribs.find(path);
            if (it == g_fileContribs.end()) continue;

            const FileContribution& contrib = it->second;
            for (uint32_t id : contrib.ownedIds) {
                ownedAppIds.insert(id);
                if (contrib.mtime != 0) {
                    uint32_t& slot = g_purchaseTime[id];
                    if (contrib.mtime > slot) slot = contrib.mtime;
                }
            }
            for (const auto& [id, key] : contrib.depotKeys) depotKeys[id] = key;
            for (const auto& [id, ov] : contrib.manifestOverrides) manifestOverrides[id] = ov;
            for (const auto& [id, token] : contrib.appTokens) appTokens[id] = token;
            for (const auto& [id, steamId] : contrib.statSteamIds) statSteamIds[id] = steamId;
            for (const auto& [id, ticket] : contrib.appTickets) appTickets[id] = ticket;
            for (const auto& [id, ticket] : contrib.encTickets) encTickets[id] = ticket;
            if (contrib.fetchCodeRef != LUA_NOREF) g_fetchCodeRef = contrib.fetchCodeRef;
            if (contrib.fetchCodeExRef != LUA_NOREF) g_fetchCodeExRef = contrib.fetchCodeExRef;
        }

        for (uint32_t id : ownedAppIds) {
            if (oldOwned.find(id) == oldOwned.end()) g_pendingAdditions.push_back(id);
        }
        for (uint32_t id : oldOwned) {
            if (ownedAppIds.find(id) == ownedAppIds.end()) g_pendingRemovals.push_back(id);
        }
    }

    static void dropFileContribution(const std::string& path, bool removeFromOrder)
    {
        auto it = g_fileContribs.find(path);
        if (it != g_fileContribs.end()) {
            releaseContributionRefs(it->second);
            g_fileContribs.erase(it);
        }
        if (removeFromOrder) eraseFileOrder(path);
    }

    static FileContribution* requireParseContribution(lua_State* L, const char* fnName)
    {
        if (!g_currentContribution) {
            luaL_error(L, "%s: may only be called while loading lua config files", fnName);
            return nullptr;
        }
        return g_currentContribution;
    }

    // ── Real binding implementations ───────────────────────────────────────

    // addappid(id [, dlc_flag [, hex_key]])
    //
    // Arg 1 (required): integer app/depot ID
    // Arg 2 (optional): integer DLC flag (accepted but not stored — kept for
    //                   script compatibility; the flag is Steam-internal info)
    // Arg 3 (optional): 64-hex-char depot decryption key string
    //
    // On success: inserts id into ownedAppIds and creates depotKeys[id] as a
    // membership marker. If a valid key is present, the marker is
    // overwritten with the 32-byte parsed key; no-key addappid keeps an empty key.
    static int impl_addappid(lua_State* L) {
        int argc = lua_gettop(L);
        if (argc == 0 || !lua_isinteger(L, 1))
            return luaL_error(L, "addappid: arg1 must be integer app/depot id");

        lua_Integer raw = lua_tointeger(L, 1);
        if (raw < 0 || raw > static_cast<lua_Integer>(UINT32_MAX))
            return luaL_error(L, "addappid: id out of uint32 range");

        uint32_t id = static_cast<uint32_t>(raw);
        FileContribution* contrib = requireParseContribution(L, "addappid");
        contrib->ownedIds.insert(id);
        contrib->depotKeys.try_emplace(id);

        // Arg 3: optional 64-hex-char depot key (arg 2 is the DLC flag).
        if (argc >= 3) {
            if (!lua_isstring(L, 3)) {
                g_pLog->warn("LuaLoader: addappid(%u): arg3 must be hex string, ignoring key\n", id);
            } else {
                const char* hexStr = lua_tostring(L, 3);
                std::vector<uint8_t> keyBytes;
                if (parseHex64(hexStr, keyBytes)) {
                    contrib->depotKeys[id] = std::move(keyBytes);
                    g_pLog->debug("LuaLoader: addappid(%u): depot key stored\n", id);
                } else {
                    g_pLog->warn("LuaLoader: addappid(%u): invalid key (need 64 hex chars), ignoring\n", id);
                }
            }
        }

        g_pLog->debug("LuaLoader: addappid(%u)\n", id);
        return 0;
    }

    // addtoken(appid, "decimal_u64_str")
    static int impl_addtoken(lua_State* L) {
        int argc = lua_gettop(L);
        if (argc < 1 || !lua_isinteger(L, 1))
            return luaL_error(L, "addtoken: arg1 must be integer appid");

        lua_Integer raw = lua_tointeger(L, 1);
        if (raw < 0 || raw > static_cast<lua_Integer>(UINT32_MAX))
            return luaL_error(L, "addtoken: appid out of uint32 range");
        uint32_t appId = static_cast<uint32_t>(raw);

        if (argc < 2)
            return 0; // token arg omitted — accept silently

        if (!lua_isstring(L, 2))
            return luaL_error(L, "addtoken: arg2 must be decimal uint64 string");

        const char* tokenStr = lua_tostring(L, 2);
        uint64_t token = 0;
        if (!parseU64Decimal(tokenStr, token))
            return luaL_error(L, "addtoken: arg2 is not a valid uint64 decimal string");

        FileContribution* contrib = requireParseContribution(L, "addtoken");
        contrib->appTokens[appId] = token;
        g_pLog->debug("LuaLoader: addtoken(%u, ...)\n", appId);
        return 0;
    }

    // setmanifestid(depotId, "gid_str" [, size])
    // The size is ALWAYS forced to 0: the GID already pins the exact manifest
    // content, so a caller-supplied size only changes the download-size *display*
    // and a wrong value can break Steam's download. The optional 3rd arg is
    // accepted for script compatibility but ignored.
    static int impl_setmanifestid(lua_State* L) {
        int argc = lua_gettop(L);
        if (argc < 2)
            return luaL_error(L, "setmanifestid: need depotId, gid_str [, size]");

        if (!lua_isinteger(L, 1))
            return luaL_error(L, "setmanifestid: arg1 (depotId) must be integer");
        if (!lua_isstring(L, 2))
            return luaL_error(L, "setmanifestid: arg2 (gid) must be decimal string");

        lua_Integer raw = lua_tointeger(L, 1);
        if (raw < 0 || raw > static_cast<lua_Integer>(UINT32_MAX))
            return luaL_error(L, "setmanifestid: depotId out of uint32 range");
        uint32_t depotId = static_cast<uint32_t>(raw);

        const char* gidStr = lua_tostring(L, 2);
        uint64_t gid = 0;
        if (!parseU64Decimal(gidStr, gid))
            return luaL_error(L, "setmanifestid: gid must be all decimal digits");

        // Forced to 0 — see the function comment above. arg3 ignored.
        const uint64_t size = 0;

        FileContribution* contrib = requireParseContribution(L, "setmanifestid");
        contrib->manifestOverrides[depotId] = ManifestOverride{ gid, size };
        g_pLog->debug("LuaLoader: setmanifestid(%u, gid=%llu, size=%llu)\n",
                      depotId, static_cast<unsigned long long>(gid),
                      static_cast<unsigned long long>(size));
        return 0;
    }

    // fetch_manifest_code(fn)
    // Captures a Lua function reference in the registry for later invocation.
    static int impl_fetch_manifest_code(lua_State* L) {
        if (lua_gettop(L) < 1 || !lua_isfunction(L, 1))
            return luaL_error(L, "fetch_manifest_code: arg1 must be a function");

        FileContribution* contrib = requireParseContribution(L, "fetch_manifest_code");
        int* refSlot = &contrib->fetchCodeRef;
        if (*refSlot != LUA_NOREF) {
            luaL_unref(L, LUA_REGISTRYINDEX, *refSlot);
        }

        lua_pushvalue(L, 1);
        *refSlot = luaL_ref(L, LUA_REGISTRYINDEX);
        g_pLog->debug("LuaLoader: fetch_manifest_code captured (ref=%d)\n", *refSlot);
        return 0;
    }

    // fetch_manifest_code_ex(fn)
    // Same as fetch_manifest_code but for the extended variant.
    static int impl_fetch_manifest_code_ex(lua_State* L) {
        if (lua_gettop(L) < 1 || !lua_isfunction(L, 1))
            return luaL_error(L, "fetch_manifest_code_ex: arg1 must be a function");

        FileContribution* contrib = requireParseContribution(L, "fetch_manifest_code_ex");
        int* refSlot = &contrib->fetchCodeExRef;
        if (*refSlot != LUA_NOREF) {
            luaL_unref(L, LUA_REGISTRYINDEX, *refSlot);
        }

        lua_pushvalue(L, 1);
        *refSlot = luaL_ref(L, LUA_REGISTRYINDEX);
        g_pLog->debug("LuaLoader: fetch_manifest_code_ex captured (ref=%d)\n", *refSlot);
        return 0;
    }

    // Parse an optional Lua table at stack index idx into a headers vector.
    // Table format: { ["Header-Name"] = "value", ... }
    // Non-string keys/values are silently skipped.
    static std::vector<std::pair<std::string, std::string>>
    parseHeadersTable(lua_State* L, int idx)
    {
        std::vector<std::pair<std::string, std::string>> hdrs;
        if (idx < 1 || idx > lua_gettop(L) || !lua_istable(L, idx))
            return hdrs;

        lua_pushnil(L); // first key
        while (lua_next(L, idx) != 0) {
            // key at -2, value at -1
            if (lua_isstring(L, -2) && lua_isstring(L, -1)) {
                hdrs.emplace_back(lua_tostring(L, -2), lua_tostring(L, -1));
            }
            lua_pop(L, 1); // pop value, keep key for next iteration
        }
        return hdrs;
    }

    // http_get(url [, headers_table]) → (body: string, status: integer)
    // On success: (body, http_status_code).  On transport error: (nil, curlcode).
    static int impl_http_get(lua_State* L) {
        if (lua_gettop(L) < 1 || !lua_isstring(L, 1))
            return luaL_error(L, "http_get: arg1 must be URL string");

        const char* url = lua_tostring(L, 1);
        auto hdrs = parseHeadersTable(L, 2);

        std::string body;
        long   status = 0;
        static const std::string noBody;
        int rc = Curl::request("GET", url, hdrs, noBody, body, status);

        if (rc == 0 /* CURLE_OK */) {
            lua_pushlstring(L, body.data(), body.size());
            lua_pushinteger(L, static_cast<lua_Integer>(status));
        } else {
            lua_pushnil(L);
            lua_pushinteger(L, rc);
        }
        return 2;
    }

    // http_post(url, body [, headers_table]) → (response: string|nil, status: integer)
    // On success: (body, http_status_code).  On transport error: (nil, curlcode).
    static int impl_http_post(lua_State* L) {
        int argc = lua_gettop(L);
        if (argc < 1 || !lua_isstring(L, 1))
            return luaL_error(L, "http_post: arg1 must be URL string");
        if (argc < 2 || !lua_isstring(L, 2))
            return luaL_error(L, "http_post: arg2 must be body string");

        const char* url = lua_tostring(L, 1);
        size_t bodyLen  = 0;
        const char* bodyPtr = lua_tolstring(L, 2, &bodyLen);
        std::string postBody(bodyPtr, bodyLen);

        auto hdrs = parseHeadersTable(L, 3);

        std::string response;
        long   status = 0;
        int rc = Curl::request("POST", url, hdrs, postBody, response, status);

        if (rc == 0 /* CURLE_OK */) {
            lua_pushlstring(L, response.data(), response.size());
            lua_pushinteger(L, static_cast<lua_Integer>(status));
        } else {
            lua_pushnil(L);
            lua_pushinteger(L, rc);
        }
        return 2;
    }

    // ── Hex helper for variable-length tickets ────────────────────────────

    // Parse a hex string of arbitrary even length into a byte vector.
    // Returns false and leaves out unchanged if the string is malformed
    // (odd length, non-hex characters, empty, or too large).
    static bool parseHexBytes(const char* hex, size_t hexLen, std::vector<uint8_t>& out) {
        if (hexLen == 0 || hexLen % 2 != 0) return false;
        if (hexLen / 2 > kMaxLuaTicketBytes) return false;
        std::vector<uint8_t> result;
        result.reserve(hexLen / 2);
        for (size_t i = 0; i < hexLen; i += 2) {
            int hi = hexNibble(hex[i]);
            int lo = hexNibble(hex[i + 1]);
            if (hi < 0 || lo < 0) return false;
            result.push_back(static_cast<uint8_t>((hi << 4) | lo));
        }
        out = std::move(result);
        return true;
    }

    // ── setappticket / seteticket real implementations ────────────────────

    // setappticket(appid, "hex_ticket")
    // Decodes hex ticket bytes, extracts SteamID AccountID from offset 8,
    // and stores in the in-memory appTickets map.
    //
    // App ownership ticket layout:
    //   [uint32 Size][uint32 Version][uint64 SteamID][...]
    //   SteamID lives at byte offset 8; we take the low 32 bits as AccountID.
    // Minimum bytes required: 16 (to cover offset 8 + 8 bytes of SteamID).
    static int impl_setappticket(lua_State* L) {
        int argc = lua_gettop(L);
        if (argc < 2)
            return luaL_error(L, "setappticket: need appid and hex string");
        if (!lua_isinteger(L, 1))
            return luaL_error(L, "setappticket: arg1 (appid) must be integer");
        if (!lua_isstring(L, 2))
            return luaL_error(L, "setappticket: arg2 (ticket) must be hex string");

        lua_Integer raw = lua_tointeger(L, 1);
        if (raw < 0 || raw > static_cast<lua_Integer>(UINT32_MAX))
            return luaL_error(L, "setappticket: appid out of uint32 range");
        uint32_t appId = static_cast<uint32_t>(raw);

        size_t hexLen = 0;
        const char* hex = lua_tolstring(L, 2, &hexLen);

        std::vector<uint8_t> bytes;
        if (!parseHexBytes(hex, hexLen, bytes)) {
            g_pLog->warn("LuaLoader: setappticket(%u): malformed or too large hex string, skipping\n", appId);
            return 0;
        }

        // Extract SteamID AccountID from byte offset 8 (little-endian uint64, take low 32 bits).
        uint32_t steamId = 0;
        if (bytes.size() >= 16) {
            uint64_t sid64 = 0;
            // Read 8 bytes at offset 8 as little-endian uint64.
            for (int i = 7; i >= 0; --i)
                sid64 = (sid64 << 8) | bytes[8 + static_cast<size_t>(i)];
            steamId = static_cast<uint32_t>(sid64 & 0xFFFFFFFFULL);
        } else {
            g_pLog->warn("LuaLoader: setappticket(%u): ticket too short (%zu bytes, need >=16) — steamId set to 0\n",
                         appId, bytes.size());
        }

        const size_t byteCount = bytes.size();
        FileContribution* contrib = requireParseContribution(L, "setappticket");
        contrib->appTickets[appId] = LuaTicket{ steamId, std::move(bytes) };
        g_pLog->debug("LuaLoader: setappticket(%u): stored %zu bytes, steamId=0x%08x\n",
                      appId, byteCount, steamId);
        return 0;
    }

	// seteticket(appid, "hex_ticket")
	// Decodes hex encrypted ticket bytes and stores in the in-memory encTickets
	// map. steamId is set to 0 because encrypted tickets do not carry a
	// plaintext SteamID — the GetSteamId hook will fall back to oneTimeSteamIdSpoof.
	// recvEncryptedAppTicket wraps these raw bytes in a protobuf response when the
	// network path needs to replay the lua-provided encrypted ticket.
	static int impl_seteticket(lua_State* L) {
        int argc = lua_gettop(L);
        if (argc < 2)
            return luaL_error(L, "seteticket: need appid and hex string");
        if (!lua_isinteger(L, 1))
            return luaL_error(L, "seteticket: arg1 (appid) must be integer");
        if (!lua_isstring(L, 2))
            return luaL_error(L, "seteticket: arg2 (ticket) must be hex string");

        lua_Integer raw = lua_tointeger(L, 1);
        if (raw < 0 || raw > static_cast<lua_Integer>(UINT32_MAX))
            return luaL_error(L, "seteticket: appid out of uint32 range");
        uint32_t appId = static_cast<uint32_t>(raw);

        size_t hexLen = 0;
        const char* hex = lua_tolstring(L, 2, &hexLen);

        std::vector<uint8_t> bytes;
        if (!parseHexBytes(hex, hexLen, bytes)) {
            g_pLog->warn("LuaLoader: seteticket(%u): malformed or too large hex string, skipping\n", appId);
            return 0;
        }

        // Encrypted tickets do not expose a plaintext SteamID; store steamId=0.
        const size_t byteCount = bytes.size();
        FileContribution* contrib = requireParseContribution(L, "seteticket");
        contrib->encTickets[appId] = LuaTicket{ 0, std::move(bytes) };
        g_pLog->debug("LuaLoader: seteticket(%u): stored %zu encrypted bytes\n",
                      appId, byteCount);
        return 0;
    }

    // ── setstat real implementation ───────────────────────────────────────

    // setstat(appid, "steamid_decimal")
    // Associates a 64-bit Steam ID with an app so that Achievements::sendMessage
    // redirects Player.GetUserStats / CMsgClientGetUserStats queries for that app
    // to the given Steam ID.
    //
    // Arg 1 (required): integer appId
    // Arg 2 (required): decimal uint64 string Steam ID (e.g. "76561198028121353")
    //
    // On success: inserts or overwrites statSteamIds[appId].
    static int impl_setstat(lua_State* L) {
        int argc = lua_gettop(L);
        if (argc < 2)
            return luaL_error(L, "setstat: need appid and steamid string");
        if (!lua_isinteger(L, 1))
            return luaL_error(L, "setstat: arg1 (appid) must be integer");
        if (!lua_isstring(L, 2))
            return luaL_error(L, "setstat: arg2 (steamid) must be decimal string");

        lua_Integer raw = lua_tointeger(L, 1);
        if (raw < 0 || raw > static_cast<lua_Integer>(UINT32_MAX))
            return luaL_error(L, "setstat: appid out of uint32 range");
        uint32_t appId = static_cast<uint32_t>(raw);

        const char* sidStr = lua_tostring(L, 2);
        uint64_t steamId = 0;
        if (!parseU64Decimal(sidStr, steamId))
            return luaL_error(L, "setstat: arg2 is not a valid uint64 decimal string");

        FileContribution* contrib = requireParseContribution(L, "setstat");
        contrib->statSteamIds[appId] = steamId;
        g_pLog->debug("LuaLoader: setstat(%u, steamid=%llu)\n",
                      appId, static_cast<unsigned long long>(steamId));
        return 0;
    }

    // ── Stub binding implementations (not implemented here) ───────────
    static int stub_downloadapp(lua_State*)                { return 0; }
    static int stub_addnonowneddepot(lua_State*)           { return 0; }
    static int stub_setnotifyondownloadcomplete(lua_State*) { return 0; }
    static int stub_setstpropertyforaccount(lua_State*)    { return 0; }

    // ── Merge lua tables into g_config ────────────────────────────────────
    // Called at the end of init() after all Lua files have been executed.
    //
    // ownedAppIds  → g_config.addedAppIds  (plain union; yaml entries kept)
    // appTokens    → g_config.appTokens    (yaml wins on conflict; lua fills gaps)
    //
    // depotKeys and manifestOverrides are lua-only (no yaml counterpart).
    //
    // THREADING NOTE: runs at init() (single-threaded startup) AND on lua/yaml
    // hot-reload from the FileWatcher thread while Steam worker threads read these
    // maps. Each write uses MTVariable::update() for an atomic RMW. Unlike a
    // union-only merge this RECOMPUTES addedAppIds/appTokens from the yaml baselines
    // ∪ the live lua tables, so a lua hot-REMOVAL (unloadFile) actually drops the id
    // from g_config instead of lingering until restart.
    void reconcileIntoConfig() {
        std::lock_guard<std::mutex> lock(g_fileMtx);  // stable read of g_purchaseTime

        // addedAppIds = yaml baseline ∪ live lua ownedAppIds.
        g_config.addedAppIds.update([](std::unordered_set<uint32_t>& dst) {
            dst = g_config.yamlAddedAppIds.get();
            for (uint32_t id : ownedAppIds) dst.insert(id);
        });

        // appTokens = yaml baseline, lua fills gaps (yaml wins on conflict).
        g_config.appTokens.update([](std::unordered_map<uint32_t, uint64_t>& dst) {
            dst = g_config.yamlAppTokens.get();
            for (const auto& [id, tok] : appTokens)
                if (dst.find(id) == dst.end()) dst[id] = tok;
        });

        // subscriptionTimestamps: lua mtimes fill gaps (yaml/real wins). Not reset
        // to a baseline (no yaml baseline kept); a removed app's stamp may linger,
        // which is harmless.
        g_config.subscriptionTimestamps.update([](std::unordered_map<uint32_t, uint32_t>& dst) {
            for (const auto& [id, mt] : g_purchaseTime)
                if (dst.find(id) == dst.end()) dst[id] = mt;
        });

        g_pLog->info("LuaLoader: reconciled %zu owned ids into g_config\n", ownedAppIds.size());
    }

    // Remove every contribution of `path` and rebuild the folded lua state.
    // Caller holds g_luaMtx + g_fileMtx.
    void unloadFile(const std::string& path) {
        dropFileContribution(path, true);
        rebuildGlobalState();
    }

    std::vector<uint32_t> takePendingAdditions() {
        std::lock_guard<std::mutex> lock(g_fileMtx);
        std::vector<uint32_t> out; out.swap(g_pendingAdditions); return out;
    }
    std::vector<uint32_t> takePendingRemovals() {
        std::lock_guard<std::mutex> lock(g_fileMtx);
        std::vector<uint32_t> out; out.swap(g_pendingRemovals); return out;
    }

    // ── Derive the Steam root directory ───────────────────────────────────
    // The authoritative source is g_modSteamClient.path (set when steamclient.so
    // loads). steamclient.so lives at <steam_root>/ubuntu12_32/steamclient.so,
    // so we go two levels up.
    // init() is called from main.cpp load() only after g_modSteamClient.path is
    // populated, so the primary path below is the normal case; the HOME fallback
    // only matters if that ever changes.
    static std::string getSteamRoot() {
        // g_modSteamClient.path is a char[] set by libmem when steamclient.so loads.
        if (g_modSteamClient.path[0] != '\0') {
            std::filesystem::path p(g_modSteamClient.path);
            // steamclient.so → ubuntu12_32/ → <steam_root>/
            auto root = p.parent_path().parent_path();
            if (!root.empty() && std::filesystem::is_directory(root)) {
                return root.string();
            }
        }
        // Fallback: standard Steam install location.
        const char* home = std::getenv("HOME");
        if (home) {
            return std::string(home) + "/.local/share/Steam";
        }
        return "";
    }

    // Parse one .lua file line-by-line, accumulating into a chunk until it
    // compiles, then executing it. A genuine syntax error logs + skips that
    // statement (does NOT discard the rest of the file); a multi-line statement
    // (luaL_loadstring reports "<eof>") keeps accumulating.
    static void parseLuaFile(const std::string& filePath) {
        if (!g_lua) {
            g_pLog->warn("LuaLoader: parseLuaFile called before init()\n");
            return;
        }
        std::ifstream file(filePath);
        if (!file) {
            g_pLog->warn("LuaLoader: failed to open %s\n", filePath.c_str());
            return;
        }
        FileContribution contrib;
        {
            std::error_code ec;
            auto ft = std::filesystem::last_write_time(filePath, ec);
            if (!ec) {
                auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    ft - decltype(ft)::clock::now() + std::chrono::system_clock::now());
                contrib.mtime = static_cast<uint32_t>(std::chrono::system_clock::to_time_t(sctp));
            }
        }
        g_currentFile = filePath;
        g_currentContribution = &contrib;
        std::string chunk, line;
        int lineNo = 0;
        while (std::getline(file, line)) {
            ++lineNo;
            if (!chunk.empty()) chunk += '\n';
            chunk += line;
            lua_settop(g_lua, 0);
            int rc = luaL_loadstring(g_lua, chunk.c_str());
            if (rc == LUA_OK) {
                if (lua_pcall(g_lua, 0, 0, 0) != LUA_OK) {
                    const char* err = lua_tostring(g_lua, -1);
                    g_pLog->warn("LuaLoader: %s:%d: %s\n", filePath.c_str(), lineNo,
                                 err ? err : "unknown error");
                    lua_pop(g_lua, 1);
                }
                chunk.clear();
            } else if (rc == LUA_ERRSYNTAX) {
                const char* err = lua_tostring(g_lua, -1);
                bool incomplete = err && std::string_view(err).find("<eof>") != std::string_view::npos;
                if (!incomplete) {
                    g_pLog->warn("LuaLoader: %s:%d: %s\n", filePath.c_str(), lineNo,
                                 err ? err : "syntax error");
                }
                lua_pop(g_lua, 1);
                if (!incomplete) chunk.clear();
            } else {
                const char* err = lua_tostring(g_lua, -1);
                g_pLog->warn("LuaLoader: %s:%d: %s\n", filePath.c_str(), lineNo,
                             err ? err : "load error");
                lua_pop(g_lua, 1);
                chunk.clear();
            }
        }
        if (!chunk.empty()) {
            g_pLog->warn("LuaLoader: %s: incomplete statement at end of file\n", filePath.c_str());
        }
        g_currentContribution = nullptr;
        g_currentFile.clear();

        auto it = g_fileContribs.find(filePath);
        if (it != g_fileContribs.end()) {
            releaseContributionRefs(it->second);
            it->second = std::move(contrib);
        } else {
            g_fileContribs.emplace(filePath, std::move(contrib));
        }
        rememberFileOrder(filePath);
    }

    // ── Directory scanner ─────────────────────────────────────────────────
    // Runs every .lua file in dir through the Lua VM.
    // Silently skips missing directories (they may not exist yet).
    static void scanDirectory(const std::string& dir) {
        if (dir.empty()) return;

        std::error_code ec;
        if (!std::filesystem::is_directory(dir, ec)) {
            g_pLog->debug("LuaLoader: skipping non-existent dir: %s\n", dir.c_str());
            return;
        }

        // Remember this dir so init() can hand it to the FileWatcher for hot-reload.
        g_luaDirs.push_back(dir);

        std::vector<std::string> files;
        for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
            if (ec) break;
            if (!entry.is_regular_file()) continue;
            if (entry.path().extension() != ".lua") continue;

            files.push_back(entry.path().string());
        }

        std::sort(files.begin(), files.end());
        for (const auto& filePath : files) {
            g_pLog->info("LuaLoader: loading %s\n", filePath.c_str());
            parseLuaFile(filePath);
        }
    }

    // ── Lua-dir hot-reload callback ────────────────────────────────────────
    void onDepotsChanged() { if (auto fn = g_onDepotsChanged.load()) fn(); }
    void setOnDepotsChanged(void (*fn)()) { g_onDepotsChanged.store(fn); }

    // FileWatcher callback (runs on the FileWatcher thread). Reparse the changed
    // .lua under BOTH locks (lua VM + file tables), then reconcile g_config and
    // fire the depots-changed seam. No-op until init() has finished building the tables.
    static void onLuaFileChanged(const std::string& path, uint32_t mask) {
        if (!initDone()) return;
        if (path.size() < 4 || path.compare(path.size() - 4, 4, ".lua") != 0) return;
        {
            // Lock order g_luaMtx → g_fileMtx (matches everywhere). parseLuaFile runs
            // the lua VM (g_luaMtx) and impl_addappid stamps the file tables
            // (g_fileMtx); unloadFile mutates both the lua maps and the file tables.
            std::lock_guard<std::mutex> luaLock(g_luaMtx);
            std::lock_guard<std::mutex> fileLock(g_fileMtx);
            const bool removed = (mask & (IN_DELETE | IN_MOVED_FROM)) != 0;
            dropFileContribution(path, removed);  // keep priority order on edits.
            if (!removed) {
                parseLuaFile(path);  // re-add (parseLuaFile sets/clears g_currentFile itself)
            }
            rebuildGlobalState();
        }
        // reconcileIntoConfig locks g_fileMtx — call it AFTER releasing the locks
        // above (std::mutex is non-recursive; double-lock would deadlock).
        reconcileIntoConfig();
        onDepotsChanged();
    }

    // ── Public entry point ────────────────────────────────────────────────
    // Set true at the very end of init(); gates the FileWatcher hot-reload path
    // (config.cpp) so it never merges while init() is still building the tables
    // on the load thread.
    std::atomic<bool> g_initDone{false};

    bool initDone() { return g_initDone.load(); }

    void init() {
        if (g_lua) return; // Already initialised.

        // Create Lua VM and open all standard libraries.
        g_lua = luaL_newstate();
        if (!g_lua) {
            g_pLog->warn("LuaLoader: failed to create lua_State\n");
            return;
        }
        luaL_openlibs(g_lua);

        // Install case-insensitive __index on _G's metatable.
        lua_getglobal(g_lua, "_G");
        if (!lua_getmetatable(g_lua, -1)) {
            lua_newtable(g_lua); // Push a fresh metatable.
        }
        lua_pushcfunction(g_lua, case_insensitive_index);
        lua_setfield(g_lua, -2, "__index");
        lua_setmetatable(g_lua, -2);
        lua_pop(g_lua, 1); // Pop _G.

        // Register all bindings. Most functions are real;
        // downloadapp/addnonowneddepot/setnotifyondownloadcomplete/setstpropertyforaccount remain stubs.
        register_func(g_lua, "addappid",                    impl_addappid);
        register_func(g_lua, "addtoken",                    impl_addtoken);
        register_func(g_lua, "setmanifestid",               impl_setmanifestid);
        register_func(g_lua, "fetch_manifest_code",         impl_fetch_manifest_code);
        register_func(g_lua, "fetch_manifest_code_ex",      impl_fetch_manifest_code_ex);
        register_func(g_lua, "http_get",                    impl_http_get);
        register_func(g_lua, "http_post",                   impl_http_post);
        register_func(g_lua, "setappticket",                impl_setappticket);
        register_func(g_lua, "seteticket",                  impl_seteticket);
        register_func(g_lua, "setstat",                     impl_setstat);
        register_func(g_lua, "downloadapp",                 stub_downloadapp);
        register_func(g_lua, "addnonowneddepot",            stub_addnonowneddepot);
        register_func(g_lua, "setnotifyondownloadcomplete", stub_setnotifyondownloadcomplete);
        register_func(g_lua, "setstpropertyforaccount",     stub_setstpropertyforaccount);

        g_pLog->info("LuaLoader: VM ready, scanning lua dirs\n");

        // ── Scan directories in priority order ────────────────────────────
        // Later directories override earlier ones (for the same depot) because
        // the binding implementations use map assignment (last write wins).

        // 1. System-wide plugin dir: {steam_root}/config/stplug-in/*.lua
        const std::string steamRoot = getSteamRoot();
        if (!steamRoot.empty()) {
            scanDirectory(steamRoot + "/config/stplug-in");
        }

        // 2. User config dir: <config>/SLSsteam/lua/*.lua
        //    Reuse g_config.getDir() which already handles XDG_CONFIG_HOME → ~/.config/SLSsteam.
        {
            std::string userLuaDir = g_config.getDir() + "/lua";
            scanDirectory(userLuaDir);
        }

        // 3. Extra directories from yaml Lua.Paths[].
        //    These are scanned after the built-in dirs so they can override entries.
        {
            const auto extraDirs = g_config.luaPaths.get();
            for (const auto& dir : extraDirs)
            {
                scanDirectory(dir);
            }
        }

        // Fold per-file contributions into public lua tables once all priority
        // dirs have been parsed. Later scanned files win on duplicate ids.
        rebuildGlobalState();

        // ── Union lua tables into g_config ────────────────────────────────
        reconcileIntoConfig();

        // Publish readiness last: the source tables (ownedAppIds/appTokens/…) are
        // now fully built and will only be read from here on, so a concurrent
        // hot-reload merge is safe.
        g_initDone = true;
        g_pLog->info("LuaLoader: init complete\n");

        // Hot-reload: watch each scanned lua dir for .lua add/edit/remove.
        g_luaWatcher = new CFileWatcher(onLuaFileChanged);
        for (const auto& dir : g_luaDirs) {
            g_luaWatcher->addDirectory(dir.c_str());
        }
        g_luaWatcher->start();
    }

    // ── Query API implementations ─────────────────────────────────────────

    // Query APIs return BY VALUE under g_luaMtx. The lua data maps are written
    // under g_luaMtx (lua VM execution at init AND the FileWatcher hot-reload
    // reparse), so a Steam hook thread reading a raw pointer could race a
    // concurrent reload (unordered_map rehash → iterator/pointer invalidation).
    // Copying under the lock makes the result safe to use after unlock.
    bool hasOwnedAppId(uint32_t appId) {
        std::lock_guard<std::mutex> lock(g_luaMtx);
        return ownedAppIds.find(appId) != ownedAppIds.end();
    }

    std::vector<uint8_t> getKey(uint32_t depotId) {
        std::lock_guard<std::mutex> lock(g_luaMtx);
        auto it = depotKeys.find(depotId);
        if (it == depotKeys.end()) return {};
        return it->second;
    }

    std::optional<ManifestOverride> getManifest(uint32_t depotId) {
        std::lock_guard<std::mutex> lock(g_luaMtx);
        auto it = manifestOverrides.find(depotId);
        if (it == manifestOverrides.end()) return std::nullopt;
        return it->second;
    }

    std::optional<LuaTicket> getAppTicket(uint32_t appId) {
        std::lock_guard<std::mutex> lock(g_luaMtx);
        auto it = appTickets.find(appId);
        if (it == appTickets.end()) return std::nullopt;
        return it->second;
    }

    std::optional<LuaTicket> getEncTicket(uint32_t appId) {
        std::lock_guard<std::mutex> lock(g_luaMtx);
        auto it = encTickets.find(appId);
        if (it == encTickets.end()) return std::nullopt;
        return it->second;
    }

    // Default Steam ID used when setstat has not been called for an app.
    static constexpr uint64_t kDefaultStatSteamId = 76561198028121353ULL;

    uint64_t getStatSteamId(uint32_t appId) {
        {
            std::lock_guard<std::mutex> lock(g_luaMtx);
            auto it = statSteamIds.find(appId);
            if (it != statSteamIds.end()) return it->second;
        }
        uint64_t apiSteamId = 0;
        if (StatsClient::fetchStatSteamId(appId, &apiSteamId))
            return apiSteamId;
        return kDefaultStatSteamId;
    }

    // ── fetchManifestCode ─────────────────────────────────────────────────
    // Tries the lua-provided callbacks first, then the built-in HTTP provider.

    // Helper: read the top Lua value as a non-zero uint64.
    // Accepts integers and decimal strings (Lua scripts may return either).
    // Returns false if the value is nil, zero, or unparseable.
    static bool readU64FromTop(lua_State* L, uint64_t& out)
    {
        if (lua_isnil(L, -1)) return false;

        if (lua_isinteger(L, -1)) {
            lua_Integer v = lua_tointeger(L, -1);
            // Reject <= 0: a negative error sentinel (e.g. -1) would otherwise
            // cast to a huge bogus uint64 and be reported as a valid code,
            // suppressing the fallback to the next provider.
            if (v <= 0) return false;
            out = static_cast<uint64_t>(v);
            return true;
        }
        if (lua_isnumber(L, -1)) {
            // Lua numbers may lose precision for large u64, but tolerate the path.
            double d = lua_tonumber(L, -1);
            // Reject non-finite or out-of-range values: casting inf/NaN or a value
            // >= 2^64 to uint64_t is undefined behaviour.
            if (!std::isfinite(d) || d <= 0.0 || d >= 18446744073709551616.0) return false;
            out = static_cast<uint64_t>(d);
            return (out != 0);
        }
        if (lua_isstring(L, -1)) {
            const char* s = lua_tostring(L, -1);
            errno = 0;
            char* end = nullptr;
            unsigned long long v = strtoull(s, &end, 10);
            if (errno != 0 || end == s || *end != '\0' || v == 0) return false;
            out = static_cast<uint64_t>(v);
            return true;
        }
        return false;
    }

    bool fetchManifestCode(uint32_t appId, uint32_t depotId, uint64_t gid, uint64_t& outCode)
    {
        if (!g_lua) {
            g_pLog->warn("LuaLoader: fetchManifestCode called before init()\n");
            return false;
        }

        // Hold g_luaMtx across both lua-provider branches (released before the
        // HTTP fallback). RAII also releases it when a branch returns a hit.
        std::unique_lock<std::mutex> luaLk(g_luaMtx);
        const int topBefore = lua_gettop(g_lua);

        // ── Branch 1: fetch_manifest_code_ex(appId, depotId, gid) ────────
        if (g_fetchCodeExRef != LUA_NOREF) {
            lua_rawgeti(g_lua, LUA_REGISTRYINDEX, g_fetchCodeExRef);
            lua_pushinteger(g_lua, static_cast<lua_Integer>(appId));
            lua_pushinteger(g_lua, static_cast<lua_Integer>(depotId));
            lua_pushinteger(g_lua, static_cast<lua_Integer>(gid));

            if (lua_pcall(g_lua, 3, 1, 0) != LUA_OK) {
                g_pLog->warn("LuaLoader: fetch_manifest_code_ex error: %s\n",
                             lua_tostring(g_lua, -1));
                lua_settop(g_lua, topBefore);
                // Fall through to branch 2 / provider on pcall failure.
            } else {
                uint64_t code = 0;
                bool ok = readU64FromTop(g_lua, code);
                lua_settop(g_lua, topBefore);
                if (ok) {
                    g_pLog->info("LuaLoader: fetchManifestCode gid=%llu via fetch_manifest_code_ex\n",
                                 static_cast<unsigned long long>(gid));
                    outCode = code;
                    return true;
                }
                g_pLog->warn("LuaLoader: fetch_manifest_code_ex returned nil/0, trying fetch_manifest_code\n");
            }
        }

        // ── Branch 2: fetch_manifest_code(gid) ───────────────────────────
        if (g_fetchCodeRef != LUA_NOREF) {
            lua_rawgeti(g_lua, LUA_REGISTRYINDEX, g_fetchCodeRef);
            lua_pushinteger(g_lua, static_cast<lua_Integer>(gid));

            if (lua_pcall(g_lua, 1, 1, 0) != LUA_OK) {
                g_pLog->warn("LuaLoader: fetch_manifest_code error: %s\n",
                             lua_tostring(g_lua, -1));
                lua_settop(g_lua, topBefore);
            } else {
                uint64_t code = 0;
                bool ok = readU64FromTop(g_lua, code);
                lua_settop(g_lua, topBefore);
                if (ok) {
                    g_pLog->info("LuaLoader: fetchManifestCode gid=%llu via fetch_manifest_code\n",
                                 static_cast<unsigned long long>(gid));
                    outCode = code;
                    return true;
                }
                g_pLog->warn("LuaLoader: fetch_manifest_code returned nil/0, falling back to provider\n");
            }
        }

        // Release the lua lock before the slow, lua-free HTTP provider call so
        // it doesn't block other concurrent fetches' lua access.
        luaLk.unlock();

        // ── Branch 3: built-in HTTP provider ─────────────────────────────
        g_pLog->info("LuaLoader: fetchManifestCode gid=%llu falling back to provider '%s'\n",
                     static_cast<unsigned long long>(gid),
                     ManifestProvider::activeProviderName());
        return ManifestProvider::fetchFromProvider(gid, outCode);
    }

} // namespace LuaLoader
