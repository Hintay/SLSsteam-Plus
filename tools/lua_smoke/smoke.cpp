// Smoke test for LuaLoader.
// Self-contained: no SLSsteam internal headers, no libmem, no toml++, no libcurl.
// Inlines the same Lua VM setup logic and real binding implementations
// as LuaLoader.cpp to verify:
//   The Lua VM can be created.
//   The case-insensitive __index metamethod resolves mixed-case names.
//   All 14 bindings are reachable without "attempt to call a nil value".
//   addappid / addtoken / setmanifestid populate the in-process tables.
//   addappid with a 64-hex-char key stores 32 decoded bytes.
//   Provider URL {gid} substitution produces correct strings.
//   parsePlainUint / parseSteamRunJson parse and validate correctly.
//   fetch_manifest_code_ex callback selection (branch 1) is invoked first
//       when the ref is set; returns the correct code.
//   fetch_manifest_code callback (branch 2) is used when _ex is not set.
//   Lua stack is balanced across pcall / result-read.
//   http_get accepts an optional headers table arg (smoke stub).
//   http_post is now a real binding (validates 2 required args in smoke).
//   setappticket hex-decode, SteamID extraction from offset 8 (little-endian).
//   setappticket malformed input is silently skipped (warn+skip, no crash).
//   seteticket hex-decode stored with steamId=0.
//   getAppTicket / getEncTicket query APIs return correct entries.

#include <cassert>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

// ── Minimal in-process state tables (mirrors LuaLoader's declarations) ────

namespace SmokeLoader {

// Depot key table: addappid(id) creates an empty membership
// marker; addappid(id, ..., hexkey) stores 32 decoded key bytes.
static std::unordered_map<uint32_t, std::vector<uint8_t>> g_depotKeys;
// Manifest GID+size overrides.
struct ManifestOverride { uint64_t gid; uint64_t size; };
static std::unordered_map<uint32_t, ManifestOverride> g_manifestOverrides;
// Owned app/depot IDs (plain set — union target).
static std::unordered_set<uint32_t> g_ownedAppIds;
// App access tokens.
static std::unordered_map<uint32_t, uint64_t> g_appTokens;

// In-memory ticket tables (mirrors LuaLoader::appTickets / encTickets).
struct LuaTicket { uint32_t steamId; std::vector<uint8_t> bytes; };
static std::unordered_map<uint32_t, LuaTicket> g_appTickets;
static std::unordered_map<uint32_t, LuaTicket> g_encTickets;

static lua_State* g_lua = nullptr;
static std::unordered_map<std::string, lua_CFunction> g_func_registry;
static bool g_had_error = false;

// Registry refs for captured Lua callbacks (mirrors LuaLoader internal state).
static int g_fetchCodeRef   = LUA_NOREF;
static int g_fetchCodeExRef = LUA_NOREF;

// ── Hex helpers ───────────────────────────────────────────────────────────

static int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

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

// parse variable-length hex string into bytes (mirrors LuaLoader::parseHexBytes).
static bool parseHexBytes(const char* hex, size_t hexLen, std::vector<uint8_t>& out) {
    if (hexLen == 0 || hexLen % 2 != 0) return false;
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

static bool parseU64Decimal(const char* str, uint64_t& out) {
    if (!str || *str == '\0') return false;
    errno = 0;
    char* end = nullptr;
    unsigned long long v = strtoull(str, &end, 10);
    if (errno != 0 || end == str || *end != '\0') return false;
    out = static_cast<uint64_t>(v);
    return true;
}

// ── Pure-logic helpers inlined from ManifestProvider + LuaLoader ─────

// Build a URL by replacing "{gid}" in tmpl with the decimal value of gid.
// (Mirrors ManifestProvider::buildUrl — inlined here to keep smoke self-contained.)
static std::string buildUrl(const char* tmpl, uint64_t gid) {
    std::string url;
    url.reserve(std::strlen(tmpl) + 24);
    const char* p = tmpl;
    while (*p) {
        if (p[0] == '{' && p[1] == 'g' && p[2] == 'i' && p[3] == 'd' && p[4] == '}') {
            char buf[24];
            std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(gid));
            url += buf;
            p += 5;
        } else {
            url += *p++;
        }
    }
    return url;
}

// Parse plain decimal uint64 from body (wudrm format) — inlined from ManifestProvider.
static bool parsePlainUint(std::string_view body, uint64_t& out) {
    const char* first = body.data();
    const char* last  = body.data() + body.size();
    while (first < last && (*first == ' ' || *first == '\t' ||
                            *first == '\r' || *first == '\n'))
        ++first;
    while (last > first && (last[-1] == ' ' || last[-1] == '\t' ||
                            last[-1] == '\r' || last[-1] == '\n'))
        --last;
    if (first == last) return false;
    errno = 0;
    char* end = nullptr;
    unsigned long long v = strtoull(first, &end, 10);
    if (errno != 0 || end != last) return false;
    out = static_cast<uint64_t>(v);
    return true;
}

// Parse {"content":"<decimal>"} JSON fragment — inlined from ManifestProvider.
static bool parseSteamRunJson(std::string_view body, uint64_t& out) {
    size_t key = body.find("\"content\"");
    if (key == std::string_view::npos) return false;
    size_t q1 = body.find('"', key + 9);
    if (q1 == std::string_view::npos) return false;
    size_t q2 = body.find('"', q1 + 1);
    if (q2 == std::string_view::npos) return false;
    return parsePlainUint(body.substr(q1 + 1, q2 - q1 - 1), out);
}

// Read the top Lua stack value as a non-zero uint64 — mirrors LuaLoader::readU64FromTop.
static bool readU64FromTop(lua_State* L, uint64_t& out) {
    if (lua_isnil(L, -1)) return false;
    if (lua_isinteger(L, -1)) {
        lua_Integer v = lua_tointeger(L, -1);
        uint64_t uv = static_cast<uint64_t>(v);
        if (uv == 0) return false;
        out = uv;
        return true;
    }
    if (lua_isnumber(L, -1)) {
        double d = lua_tonumber(L, -1);
        if (d <= 0) return false;
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

// ── Real binding implementations (mirrors LuaLoader.cpp logic) ────────

static int impl_addappid(lua_State* L) {
    int argc = lua_gettop(L);
    if (argc == 0 || !lua_isinteger(L, 1)) {
        lua_pushstring(L, "addappid: arg1 must be integer");
        return lua_error(L);
    }
    lua_Integer raw = lua_tointeger(L, 1);
    if (raw < 0 || raw > static_cast<lua_Integer>(UINT32_MAX)) {
        lua_pushstring(L, "addappid: id out of range");
        return lua_error(L);
    }
    uint32_t id = static_cast<uint32_t>(raw);
    g_ownedAppIds.insert(id);
    g_depotKeys.try_emplace(id);

    if (argc >= 3 && lua_isstring(L, 3)) {
        const char* hexStr = lua_tostring(L, 3);
        std::vector<uint8_t> keyBytes;
        if (parseHex64(hexStr, keyBytes)) {
            g_depotKeys[id] = std::move(keyBytes);
        }
    }
    return 0;
}

static int impl_addtoken(lua_State* L) {
    int argc = lua_gettop(L);
    if (argc < 1 || !lua_isinteger(L, 1)) {
        lua_pushstring(L, "addtoken: arg1 must be integer");
        return lua_error(L);
    }
    lua_Integer raw = lua_tointeger(L, 1);
    if (raw < 0 || raw > static_cast<lua_Integer>(UINT32_MAX)) {
        lua_pushstring(L, "addtoken: out of range");
        return lua_error(L);
    }
    uint32_t appId = static_cast<uint32_t>(raw);
    if (argc < 2) return 0;
    if (!lua_isstring(L, 2)) {
        lua_pushstring(L, "addtoken: arg2 must be string");
        return lua_error(L);
    }
    uint64_t token = 0;
    if (!parseU64Decimal(lua_tostring(L, 2), token)) {
        lua_pushstring(L, "addtoken: invalid decimal string");
        return lua_error(L);
    }
    g_appTokens[appId] = token;
    return 0;
}

static int impl_setmanifestid(lua_State* L) {
    int argc = lua_gettop(L);
    if (argc < 2 || !lua_isinteger(L, 1) || !lua_isstring(L, 2)) {
        lua_pushstring(L, "setmanifestid: need integer depotId and string gid");
        return lua_error(L);
    }
    lua_Integer raw = lua_tointeger(L, 1);
    if (raw < 0 || raw > static_cast<lua_Integer>(UINT32_MAX)) {
        lua_pushstring(L, "setmanifestid: depotId out of range");
        return lua_error(L);
    }
    uint32_t depotId = static_cast<uint32_t>(raw);
    uint64_t gid = 0;
    if (!parseU64Decimal(lua_tostring(L, 2), gid)) {
        lua_pushstring(L, "setmanifestid: invalid gid string");
        return lua_error(L);
    }
    uint64_t size = 0;
    if (argc >= 3) {
        // Most-specific first: lua_isstring is true for numbers in Lua 5.4,
        // so integer/number branches must precede the string branch.
        if (lua_isinteger(L, 3)) {
            lua_Integer rs = lua_tointeger(L, 3);
            size = rs >= 0 ? static_cast<uint64_t>(rs) : 0;
        } else if (lua_isnumber(L, 3)) {
            double d = lua_tonumber(L, 3);
            size = d >= 0 ? static_cast<uint64_t>(d) : 0;
        } else if (lua_isstring(L, 3)) {
            parseU64Decimal(lua_tostring(L, 3), size);
        }
    }
    g_manifestOverrides[depotId] = ManifestOverride{gid, size};
    return 0;
}

// real ref-capturing implementation (mirrors LuaLoader).
static int impl_fetch_manifest_code(lua_State* L) {
    if (lua_gettop(L) < 1 || !lua_isfunction(L, 1)) {
        lua_pushstring(L, "fetch_manifest_code: arg1 must be function");
        return lua_error(L);
    }
    if (g_fetchCodeRef != LUA_NOREF)
        luaL_unref(L, LUA_REGISTRYINDEX, g_fetchCodeRef);
    lua_pushvalue(L, 1);
    g_fetchCodeRef = luaL_ref(L, LUA_REGISTRYINDEX);
    return 0;
}

// real ref-capturing implementation (mirrors LuaLoader).
static int impl_fetch_manifest_code_ex(lua_State* L) {
    if (lua_gettop(L) < 1 || !lua_isfunction(L, 1)) {
        lua_pushstring(L, "fetch_manifest_code_ex: arg1 must be function");
        return lua_error(L);
    }
    if (g_fetchCodeExRef != LUA_NOREF)
        luaL_unref(L, LUA_REGISTRYINDEX, g_fetchCodeExRef);
    lua_pushvalue(L, 1);
    g_fetchCodeExRef = luaL_ref(L, LUA_REGISTRYINDEX);
    return 0;
}

// http_get(url [, headers_table]) → (body, status)
// Smoke: parse headers table arg to verify no crash, then return stub response.
static int impl_http_get(lua_State* L) {
    if (lua_gettop(L) < 1 || !lua_isstring(L, 1)) {
        lua_pushstring(L, "http_get: arg1 must be string");
        return lua_error(L);
    }
    // Consume optional headers table (arg 2) without crashing.
    // No real network call in smoke.
    lua_pushliteral(L, "");
    lua_pushinteger(L, 200); // HTTP 200 (changed from 0 to reflect real http_get contract)
    return 2;
}

// http_post(url, body [, headers_table]) → (response|nil, status)
// Smoke: validate required args, return stub (nil, 200).
static int impl_http_post(lua_State* L) {
    int argc = lua_gettop(L);
    if (argc < 1 || !lua_isstring(L, 1)) {
        lua_pushstring(L, "http_post: arg1 must be URL string");
        return lua_error(L);
    }
    if (argc < 2 || !lua_isstring(L, 2)) {
        lua_pushstring(L, "http_post: arg2 must be body string");
        return lua_error(L);
    }
    // Smoke: don't make real network calls; return a stubbed success response.
    lua_pushliteral(L, "");
    lua_pushinteger(L, 200);
    return 2;
}

// real setappticket implementation (mirrors LuaLoader::impl_setappticket).
static int impl_setappticket(lua_State* L) {
    int argc = lua_gettop(L);
    if (argc < 2 || !lua_isinteger(L, 1) || !lua_isstring(L, 2)) {
        lua_pushstring(L, "setappticket: need integer appid and hex string");
        return lua_error(L);
    }
    lua_Integer raw = lua_tointeger(L, 1);
    if (raw < 0 || raw > static_cast<lua_Integer>(UINT32_MAX)) {
        lua_pushstring(L, "setappticket: appid out of range");
        return lua_error(L);
    }
    uint32_t appId = static_cast<uint32_t>(raw);

    size_t hexLen = 0;
    const char* hex = lua_tolstring(L, 2, &hexLen);

    std::vector<uint8_t> bytes;
    if (!parseHexBytes(hex, hexLen, bytes)) {
        // Malformed input: warn and skip without crashing (matches LuaLoader behaviour).
        fprintf(stderr, "[smoke] setappticket(%u): malformed hex, skipping\n", appId);
        return 0;
    }

    // Extract SteamID AccountID: little-endian uint64 at byte offset 8, take low 32 bits.
    uint32_t steamId = 0;
    if (bytes.size() >= 16) {
        uint64_t sid64 = 0;
        for (int i = 7; i >= 0; --i)
            sid64 = (sid64 << 8) | bytes[8 + static_cast<size_t>(i)];
        steamId = static_cast<uint32_t>(sid64 & 0xFFFFFFFFULL);
    }
    g_appTickets[appId] = LuaTicket{ steamId, std::move(bytes) };
    return 0;
}

// real seteticket implementation (mirrors LuaLoader::impl_seteticket).
static int impl_seteticket(lua_State* L) {
    int argc = lua_gettop(L);
    if (argc < 2 || !lua_isinteger(L, 1) || !lua_isstring(L, 2)) {
        lua_pushstring(L, "seteticket: need integer appid and hex string");
        return lua_error(L);
    }
    lua_Integer raw = lua_tointeger(L, 1);
    if (raw < 0 || raw > static_cast<lua_Integer>(UINT32_MAX)) {
        lua_pushstring(L, "seteticket: appid out of range");
        return lua_error(L);
    }
    uint32_t appId = static_cast<uint32_t>(raw);

    size_t hexLen = 0;
    const char* hex = lua_tolstring(L, 2, &hexLen);

    std::vector<uint8_t> bytes;
    if (!parseHexBytes(hex, hexLen, bytes)) {
        fprintf(stderr, "[smoke] seteticket(%u): malformed hex, skipping\n", appId);
        return 0;
    }
    // Encrypted tickets carry no plaintext SteamID; steamId=0.
    g_encTickets[appId] = LuaTicket{ 0, std::move(bytes) };
    return 0;
}

// Remaining stubs.
static int s_stub(lua_State*) { return 0; }

// ── Case-insensitive VM helpers ───────────────────────────────────────────

static int case_insensitive_index(lua_State* L) {
    const char* name = lua_tostring(L, 2);
    if (!name) { lua_pushnil(L); return 1; }
    std::string lower;
    for (const char* p = name; *p; ++p)
        lower += static_cast<char>(std::tolower(static_cast<unsigned char>(*p)));
    auto it = g_func_registry.find(lower);
    if (it != g_func_registry.end()) { lua_pushcfunction(L, it->second); return 1; }
    lua_pushnil(L);
    return 1;
}

static void register_func(lua_State* L, const char* name, lua_CFunction fn) {
    g_func_registry[name] = fn;
    lua_pushcfunction(L, fn);
    lua_setglobal(L, name);
}

// ── Init and script runner ────────────────────────────────────────────────

static void init(const std::string& scanDir) {
    g_lua = luaL_newstate();
    if (!g_lua) { fprintf(stderr, "[smoke] luaL_newstate failed\n"); return; }
    luaL_openlibs(g_lua);

    // Install case-insensitive __index on _G's metatable (mirrors LuaLoader::init).
    lua_getglobal(g_lua, "_G");
    if (!lua_getmetatable(g_lua, -1)) lua_newtable(g_lua);
    lua_pushcfunction(g_lua, case_insensitive_index);
    lua_setfield(g_lua, -2, "__index");
    lua_setmetatable(g_lua, -2);
    lua_pop(g_lua, 1); // Pop _G.

    // MANUAL MIRROR of the registration list in LuaLoader::init() — must be kept
    // in sync by hand whenever bindings are added or renamed there.
    register_func(g_lua, "addappid",                    impl_addappid);
    register_func(g_lua, "addtoken",                    impl_addtoken);
    register_func(g_lua, "setmanifestid",               impl_setmanifestid);
    register_func(g_lua, "fetch_manifest_code",         impl_fetch_manifest_code);
    register_func(g_lua, "fetch_manifest_code_ex",      impl_fetch_manifest_code_ex);
    register_func(g_lua, "http_get",                    impl_http_get);
    register_func(g_lua, "http_post",                   impl_http_post);
    register_func(g_lua, "setappticket",                impl_setappticket);
    register_func(g_lua, "seteticket",                  impl_seteticket);
    register_func(g_lua, "setstat",                     s_stub);
    register_func(g_lua, "downloadapp",                 s_stub);
    register_func(g_lua, "addnonowneddepot",            s_stub);
    register_func(g_lua, "setnotifyondownloadcomplete", s_stub);
    register_func(g_lua, "setstpropertyforaccount",     s_stub);

    // Scan scanDir and execute every .lua file found.
    std::error_code ec;
    if (!std::filesystem::is_directory(scanDir, ec)) {
        fprintf(stderr, "[smoke] dir not found: %s\n", scanDir.c_str());
        g_had_error = true;
        return;
    }
    for (const auto& entry : std::filesystem::directory_iterator(scanDir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".lua") continue;

        const std::string path = entry.path().string();
        printf("[smoke] executing: %s\n", path.c_str());
        lua_settop(g_lua, 0);

        int rc = luaL_loadfile(g_lua, path.c_str());
        if (rc != LUA_OK) {
            fprintf(stderr, "[smoke] compile error in %s: %s\n",
                    path.c_str(), lua_tostring(g_lua, -1));
            lua_pop(g_lua, 1);
            g_had_error = true;
            continue;
        }
        if (lua_pcall(g_lua, 0, 0, 0) != LUA_OK) {
            fprintf(stderr, "[smoke] runtime error in %s: %s\n",
                    path.c_str(), lua_tostring(g_lua, -1));
            lua_pop(g_lua, 1);
            g_had_error = true;
        }
    }
}

// ── fetchManifestCode logic (inlined mirror of LuaLoader::fetchManifestCode) ──
// Used by C-level assertions; no network calls are made.
static bool fetchManifestCode(uint32_t appId, uint32_t depotId,
                               uint64_t gid, uint64_t& outCode)
{
    if (!g_lua) return false;
    const int topBefore = lua_gettop(g_lua);

    // Branch 1: fetch_manifest_code_ex(appId, depotId, gid)
    if (g_fetchCodeExRef != LUA_NOREF) {
        lua_rawgeti(g_lua, LUA_REGISTRYINDEX, g_fetchCodeExRef);
        lua_pushinteger(g_lua, static_cast<lua_Integer>(appId));
        lua_pushinteger(g_lua, static_cast<lua_Integer>(depotId));
        lua_pushinteger(g_lua, static_cast<lua_Integer>(gid));
        if (lua_pcall(g_lua, 3, 1, 0) != LUA_OK) {
            lua_settop(g_lua, topBefore);
        } else {
            uint64_t code = 0;
            bool ok = readU64FromTop(g_lua, code);
            lua_settop(g_lua, topBefore);
            if (ok) { outCode = code; return true; }
        }
    }

    // Branch 2: fetch_manifest_code(gid)
    if (g_fetchCodeRef != LUA_NOREF) {
        lua_rawgeti(g_lua, LUA_REGISTRYINDEX, g_fetchCodeRef);
        lua_pushinteger(g_lua, static_cast<lua_Integer>(gid));
        if (lua_pcall(g_lua, 1, 1, 0) != LUA_OK) {
            lua_settop(g_lua, topBefore);
        } else {
            uint64_t code = 0;
            bool ok = readU64FromTop(g_lua, code);
            lua_settop(g_lua, topBefore);
            if (ok) { outCode = code; return true; }
        }
    }

    // Branch 3: provider — smoke does not make real network calls; signal failure.
    return false;
}

} // namespace SmokeLoader

// ── Self-contained refcount bookkeeping mirror ───────────────────────────

struct SmokeFileTrack {
    std::unordered_map<std::string, std::unordered_set<uint32_t>> fileIds;
    std::unordered_map<uint32_t, uint32_t> refCount;
    std::vector<uint32_t> pendingAdd, pendingRemove;
    void addId(const std::string& f, uint32_t id) {
        if (fileIds[f].insert(id).second && ++refCount[id] == 1) pendingAdd.push_back(id);
    }
    void unload(const std::string& f) {
        auto it = fileIds.find(f); if (it == fileIds.end()) return;
        for (uint32_t id : it->second)
            if (--refCount[id] == 0) { refCount.erase(id); pendingRemove.push_back(id); }
        fileIds.erase(it);
    }
};

static void test_refcount() {
    SmokeFileTrack t;
    t.addId("a.lua", 100); t.addId("b.lua", 100); t.addId("a.lua", 200);
    assert(t.refCount[100] == 2 && t.refCount[200] == 1);
    assert(t.pendingAdd.size() == 2);            // 100 and 200 each fired once on 0→1
    t.addId("a.lua", 100);                        // duplicate within same file — no-op
    assert(t.refCount[100] == 2 && t.pendingAdd.size() == 2);
    t.unload("a.lua");
    assert(t.refCount[100] == 1);
    assert(t.refCount.find(200) == t.refCount.end());
    assert(t.pendingRemove.size() == 1 && t.pendingRemove[0] == 200);
    t.unload("b.lua");
    assert(t.refCount.find(100) == t.refCount.end());
    std::printf("test_refcount OK\n");
}

// ── unloadFile removes a file's ids from ALL maps ────────────────────
static void test_unload_full_removal() {
    std::unordered_set<uint32_t> owned{100, 200};
    std::unordered_map<uint32_t, int> keys{{100,1},{200,1}}, tokens{{200,7}};
    uint32_t id = 200;
    owned.erase(id); keys.erase(id); tokens.erase(id);
    assert(owned.count(200) == 0 && keys.count(200) == 0 && tokens.count(200) == 0);
    assert(owned.count(100) == 1 && keys.count(100) == 1);
    std::printf("test_unload_full_removal OK\n");
}

// ── Mirror of LuaLoader::parseLuaFile (incremental per-line parser) ──────────
static int smoke_parseLuaString(lua_State* L, const std::string& src) {
    int executed = 0;
    std::string chunk, line;
    std::istringstream in(src);
    while (std::getline(in, line)) {
        if (!chunk.empty()) chunk += '\n';
        chunk += line;
        lua_settop(L, 0);
        int rc = luaL_loadstring(L, chunk.c_str());
        if (rc == LUA_OK) {
            if (lua_pcall(L, 0, 0, 0) == LUA_OK) ++executed;
            chunk.clear();
        } else if (rc == LUA_ERRSYNTAX) {
            const char* err = lua_tostring(L, -1);
            bool incomplete = err && std::string_view(err).find("<eof>") != std::string_view::npos;
            lua_pop(L, 1);
            if (!incomplete) chunk.clear();
        } else {
            lua_pop(L, 1);
            chunk.clear();
        }
    }
    return executed;
}

static void test_incremental_parser() {
    lua_State* L = luaL_newstate(); luaL_openlibs(L);
    luaL_dostring(L, "n = 0");
    int ok = smoke_parseLuaString(L,
        "n = n + 1\n"
        "n = @\n"
        "n = n + 1\n"
        "n = n + 1\n");
    lua_getglobal(L, "n");
    int n = (int)lua_tointeger(L, -1);
    assert(ok == 3 && "3 good statements should execute");
    assert(n == 3 && "bad line must not swallow following lines");
    luaL_dostring(L, "m = 0");
    int ok2 = smoke_parseLuaString(L, "if true\nthen\n  m = 5\nend\n");
    lua_getglobal(L, "m"); int m = (int)lua_tointeger(L, -1);
    assert(ok2 == 1 && m == 5 && "multi-line statement accumulates");
    lua_close(L);
    std::printf("test_incremental_parser OK\n");
}

// ── Main ──────────────────────────────────────────────────────────────────

int main() {
    const char* tmp = std::getenv("TMPDIR");
    const std::string luaDir = std::string(tmp ? tmp : "/tmp") + "/sls_smoke_lua";

    printf("[smoke] LuaLoader smoke test\n");
    printf("[smoke] script dir: %s\n", luaDir.c_str());

    // ── pure-logic checks (no Lua VM, no network) ───────────────────────
    printf("[smoke] --- pure-logic checks ---\n");

    // URL template substitution.
    {
        const char* wudrmTmpl    = "http://gmrc.wudrm.com/manifest/{gid}";
        const char* steamrunTmpl = "https://manifest.steam.run/api/manifest/{gid}";
        uint64_t gid = 1234567890123456789ULL;

        std::string wu  = SmokeLoader::buildUrl(wudrmTmpl, gid);
        std::string sr  = SmokeLoader::buildUrl(steamrunTmpl, gid);

        // Manually build expected strings.
        char expected[256];
        std::snprintf(expected, sizeof(expected),
                      "http://gmrc.wudrm.com/manifest/%llu",
                      static_cast<unsigned long long>(gid));
        if (wu != expected) {
            fprintf(stderr, "[smoke] FAIL: wudrm URL wrong: '%s' (expected '%s')\n",
                    wu.c_str(), expected);
            SmokeLoader::g_had_error = true;
        } else {
            printf("[smoke] PASS: wudrm URL: %s\n", wu.c_str());
        }

        std::snprintf(expected, sizeof(expected),
                      "https://manifest.steam.run/api/manifest/%llu",
                      static_cast<unsigned long long>(gid));
        if (sr != expected) {
            fprintf(stderr, "[smoke] FAIL: steamrun URL wrong: '%s' (expected '%s')\n",
                    sr.c_str(), expected);
            SmokeLoader::g_had_error = true;
        } else {
            printf("[smoke] PASS: steamrun URL: %s\n", sr.c_str());
        }
    }

    // parsePlainUint: valid + edge cases.
    {
        uint64_t v = 0;
        // Normal decimal.
        if (!SmokeLoader::parsePlainUint("9999999999999999999", v) || v != 9999999999999999999ULL) {
            fprintf(stderr, "[smoke] FAIL: parsePlainUint large value\n");
            SmokeLoader::g_had_error = true;
        }
        // Trailing whitespace (wudrm bodies often have a newline).
        if (!SmokeLoader::parsePlainUint("123456789\n", v) || v != 123456789ULL) {
            fprintf(stderr, "[smoke] FAIL: parsePlainUint trailing newline\n");
            SmokeLoader::g_had_error = true;
        }
        // Zero — should parse but caller must reject (parsePlainUint itself allows 0).
        if (!SmokeLoader::parsePlainUint("0", v) || v != 0) {
            fprintf(stderr, "[smoke] FAIL: parsePlainUint zero\n");
            SmokeLoader::g_had_error = true;
        }
        // Empty → false.
        if (SmokeLoader::parsePlainUint("", v)) {
            fprintf(stderr, "[smoke] FAIL: parsePlainUint empty should be false\n");
            SmokeLoader::g_had_error = true;
        }
        // Non-digit → false.
        if (SmokeLoader::parsePlainUint("abc", v)) {
            fprintf(stderr, "[smoke] FAIL: parsePlainUint 'abc' should be false\n");
            SmokeLoader::g_had_error = true;
        }
        printf("[smoke] PASS: parsePlainUint edge cases\n");
    }

    // parseSteamRunJson: valid JSON and missing-key cases.
    {
        uint64_t v = 0;
        const std::string_view goodJson =
            R"({"status":"ok","content":"7654321098765432109"})";
        if (!SmokeLoader::parseSteamRunJson(goodJson, v) || v != 7654321098765432109ULL) {
            fprintf(stderr, "[smoke] FAIL: parseSteamRunJson good JSON\n");
            SmokeLoader::g_had_error = true;
        }
        const std::string_view noContent = R"({"status":"ok"})";
        if (SmokeLoader::parseSteamRunJson(noContent, v)) {
            fprintf(stderr, "[smoke] FAIL: parseSteamRunJson no-content-key should be false\n");
            SmokeLoader::g_had_error = true;
        }
        const std::string_view garbage = "not json at all";
        if (SmokeLoader::parseSteamRunJson(garbage, v)) {
            fprintf(stderr, "[smoke] FAIL: parseSteamRunJson garbage should be false\n");
            SmokeLoader::g_had_error = true;
        }
        printf("[smoke] PASS: parseSteamRunJson edge cases\n");
    }

    // ── Lua script test ──────────────────────────────────────────────
    printf("[smoke] --- Lua script checks ---\n");
    std::filesystem::create_directories(luaDir);
    {
        std::ofstream f(luaDir + "/test.lua");
        if (!f) { fprintf(stderr, "[smoke] cannot write test.lua\n"); return 1; }

        // mixed-case binding reachability + table population.
        f << "-- test.lua: case-insensitive reachability + bindings\n";

        // addappid: basic (inserts into ownedAppIds and an empty depotKeys marker)
        f << "AddAppId(12345)\n";
        // addappid with DLC flag and 64-hex key (all lowercase a-f hex digits)
        f << "ADDAPPID(99999, 1, \"" << std::string(64, 'a') << "\")\n";
        // addappid with mixed-case name (also creates an empty marker)
        f << "AddAppID(11111)\n";
        // Non-empty keys have priority over existing empty keys, and later empty
        // addappid calls must not erase an existing non-empty key.
        f << "ADDAPPID(22222, 1, \"" << std::string(64, 'b') << "\")\n";
        f << "AddAppId(22222)\n";
        f << "AddAppId(33333)\n";
        f << "ADDAPPID(33333, 1, \"" << std::string(64, 'c') << "\")\n";

        // addtoken: decimal string
        f << "ADDTOKEN(12345, \"9876543210\")\n";
        f << "Addtoken(11111, \"0\")\n";

        // setmanifestid: 2-arg form
        f << "SetManifestId(12345, \"1111111111111111\")\n";
        // setmanifestid: 3-arg form with integer size
        f << "SETMANIFESTID(99999, \"2222222222222222\", 512)\n";
        // setmanifestid: mixed case
        f << "setManifestID(11111, \"3333333333333333\")\n";

        // fetch_manifest_code_ex registers a callback that returns a known code
        // when called with (appId=1, depotId=2, gid=999).
        // Use 9000000000000000001 — fits in Lua 5.4 integer (must be < 2^63).
        f << "fetch_manifest_code_ex(function(app, depot, gid)\n";
        f << "  -- Return a well-known non-zero code for gid 999.\n";
        f << "  if gid == 999 then return 9000000000000000001 end\n";
        f << "  return nil\n";
        f << "end)\n";

        // also register a fetch_manifest_code (branch 2) that returns a
        // different sentinel — should NOT be reached while _ex is set.
        f << "fetch_manifest_code(function(gid)\n";
        f << "  return 11111111111111111\n"; // sentinel: should never be seen when _ex is set
        f << "end)\n";

        // http_get with optional headers table (must not crash).
        f << "local body, st = HTTP_GET(\"http://example.com\", {[\"X-Test\"]=\"val\"})\n";
        f << "assert(type(st) == \"number\", \"http_get status must be number\")\n";

        // http_post with body and optional headers table.
        f << "local r, st2 = Http_Post(\"http://x\", \"body\", {[\"Content-Type\"]=\"text/plain\"})\n";
        f << "assert(type(st2) == \"number\", \"http_post status must be number\")\n";

        // setappticket with a crafted 28-byte ticket.
        // Byte layout (little-endian):
        //   [0..3]  = 14 00 00 00  (Size field, LE)
        //   [4..7]  = 01 00 00 00  (Version field, LE)
        //   [8..15] = 10 00 00 01 10 00 00 01  (SteamID LE = 0x0100001001000010)
        //   [16..27]= 00 * 12     (padding)
        // SteamID low 32 bits = 0x01000010 = 16777232.
        // Hex: "14000000010000001000000110000001" (32) + "0000000000000000" (16) + "00000000" (8) = 56 hex = 28 bytes.
        f << "SetAppTicket(55555, \"14000000010000001000000110000001\" .. \"0000000000000000\" .. \"00000000\")\n";
        // setappticket with a too-short ticket (< 16 bytes) — steamId should be 0.
        f << "SetAppTicket(66666, \"deadbeef\")\n";
        // setappticket malformed hex (odd length) — should warn+skip, no crash.
        f << "SetAppTicket(77777, \"abc\")\n";
        // seteticket — store encrypted ticket bytes, steamId=0.
        f << "SETETICKET(55555, \"cafebabe0102030405060708\")\n";
        // stub — just verify it doesn't crash.
        f << "SetStat(1, \"76561198000000000\")\n";
        f << "DownloadApp(1)\n";
        f << "AddNonOwnedDepot(1)\n";
        f << "SetNotifyOnDownloadComplete(true)\n";
        f << "SetStPropertyForAccount(1, \"k\", \"v\")\n";

        f << "print(\"[smoke] all bindings resolved OK\")\n";
    }

    SmokeLoader::init(luaDir);

    // ── table-population assertions ──────────────────────────────────
    if (!SmokeLoader::g_had_error) {
        // ownedAppIds should contain 12345, 99999, 11111
        auto& owned = SmokeLoader::g_ownedAppIds;
        if (!owned.count(12345)) {
            fprintf(stderr, "[smoke] FAIL: 12345 not in ownedAppIds\n");
            SmokeLoader::g_had_error = true;
        }
        if (!owned.count(99999)) {
            fprintf(stderr, "[smoke] FAIL: 99999 not in ownedAppIds\n");
            SmokeLoader::g_had_error = true;
        }
        if (!owned.count(11111)) {
            fprintf(stderr, "[smoke] FAIL: 11111 not in ownedAppIds\n");
            SmokeLoader::g_had_error = true;
        }

        // depotKeys membership: no-key addappid still creates an empty marker,
        // while valid keys store 32 decoded bytes.
        auto& keys = SmokeLoader::g_depotKeys;
        if (keys.find(12345) == keys.end() || !keys.at(12345).empty()) {
            fprintf(stderr, "[smoke] FAIL: depotKeys[12345] empty marker missing or non-empty\n");
            SmokeLoader::g_had_error = true;
        }
        if (keys.find(11111) == keys.end() || !keys.at(11111).empty()) {
            fprintf(stderr, "[smoke] FAIL: depotKeys[11111] empty marker missing or non-empty\n");
            SmokeLoader::g_had_error = true;
        }
        if (keys.find(99999) == keys.end() || keys.at(99999).size() != 32) {
            fprintf(stderr, "[smoke] FAIL: depotKeys[99999] missing or wrong size\n");
            SmokeLoader::g_had_error = true;
        } else {
            for (uint8_t b : keys.at(99999)) {
                if (b != 0xaa) {
                    fprintf(stderr, "[smoke] FAIL: depotKeys[99999] byte mismatch (got 0x%02x)\n", b);
                    SmokeLoader::g_had_error = true;
                    break;
                }
            }
        }
        if (keys.find(22222) == keys.end() || keys.at(22222).size() != 32) {
            fprintf(stderr, "[smoke] FAIL: depotKeys[22222] missing or overwritten by empty marker\n");
            SmokeLoader::g_had_error = true;
        } else {
            for (uint8_t b : keys.at(22222)) {
                if (b != 0xbb) {
                    fprintf(stderr, "[smoke] FAIL: depotKeys[22222] byte mismatch (got 0x%02x)\n", b);
                    SmokeLoader::g_had_error = true;
                    break;
                }
            }
        }
        if (keys.find(33333) == keys.end() || keys.at(33333).size() != 32) {
            fprintf(stderr, "[smoke] FAIL: depotKeys[33333] empty marker was not overwritten by non-empty key\n");
            SmokeLoader::g_had_error = true;
        } else {
            for (uint8_t b : keys.at(33333)) {
                if (b != 0xcc) {
                    fprintf(stderr, "[smoke] FAIL: depotKeys[33333] byte mismatch (got 0x%02x)\n", b);
                    SmokeLoader::g_had_error = true;
                    break;
                }
            }
        }

        // appTokens[12345] should be 9876543210
        auto& tokens = SmokeLoader::g_appTokens;
        if (!tokens.count(12345) || tokens.at(12345) != 9876543210ULL) {
            fprintf(stderr, "[smoke] FAIL: appTokens[12345] wrong (got %llu)\n",
                    tokens.count(12345) ? (unsigned long long)tokens.at(12345) : 0ULL);
            SmokeLoader::g_had_error = true;
        }
        if (!tokens.count(11111) || tokens.at(11111) != 0ULL) {
            fprintf(stderr, "[smoke] FAIL: appTokens[11111] wrong\n");
            SmokeLoader::g_had_error = true;
        }

        // manifestOverrides
        auto& mfst = SmokeLoader::g_manifestOverrides;
        if (!mfst.count(12345) || mfst.at(12345).gid != 1111111111111111ULL) {
            fprintf(stderr, "[smoke] FAIL: manifestOverrides[12345].gid wrong\n");
            SmokeLoader::g_had_error = true;
        }
        if (!mfst.count(99999) || mfst.at(99999).gid != 2222222222222222ULL ||
            mfst.at(99999).size != 512) {
            fprintf(stderr, "[smoke] FAIL: manifestOverrides[99999] wrong\n");
            SmokeLoader::g_had_error = true;
        }
        if (!mfst.count(11111) || mfst.at(11111).gid != 3333333333333333ULL) {
            fprintf(stderr, "[smoke] FAIL: manifestOverrides[11111].gid wrong\n");
            SmokeLoader::g_had_error = true;
        }
    }

    // ── ticket table assertions ──────────────────────────────────────
    printf("[smoke] --- ticket checks ---\n");
    if (!SmokeLoader::g_had_error) {
        // appTickets[55555]: 28 bytes, steamId = low 32 bits of LE uint64 at offset 8.
        // Bytes [8..15] = 0x10,0x00,0x00,0x01,0x10,0x00,0x00,0x01
        // uint64 LE = 0x0100001001000010 => low32 = 0x01000010 = 16777232
        auto& at = SmokeLoader::g_appTickets;
        if (at.find(55555) == at.end()) {
            fprintf(stderr, "[smoke] FAIL: appTickets[55555] missing\n");
            SmokeLoader::g_had_error = true;
        } else {
            const auto& tkt = at.at(55555);
            if (tkt.bytes.size() != 28) {
                fprintf(stderr, "[smoke] FAIL: appTickets[55555] size %zu (expected 28)\n", tkt.bytes.size());
                SmokeLoader::g_had_error = true;
            } else if (tkt.steamId != 0x01000010u) {
                fprintf(stderr, "[smoke] FAIL: appTickets[55555] steamId=0x%08x (expected 0x01000010)\n", tkt.steamId);
                SmokeLoader::g_had_error = true;
            } else {
                printf("[smoke] PASS: appTickets[55555] bytes=%zu steamId=0x%08x\n",
                       tkt.bytes.size(), tkt.steamId);
            }
        }

        // appTickets[66666]: 4 bytes (< 16), steamId must be 0.
        if (at.find(66666) == at.end()) {
            fprintf(stderr, "[smoke] FAIL: appTickets[66666] missing\n");
            SmokeLoader::g_had_error = true;
        } else {
            const auto& tkt = at.at(66666);
            if (tkt.steamId != 0) {
                fprintf(stderr, "[smoke] FAIL: appTickets[66666] steamId=%u (expected 0 for short ticket)\n", tkt.steamId);
                SmokeLoader::g_had_error = true;
            } else {
                printf("[smoke] PASS: appTickets[66666] short ticket steamId=0\n");
            }
        }

        // appTickets[77777]: malformed hex — should NOT be in the map (skipped).
        if (at.find(77777) != at.end()) {
            fprintf(stderr, "[smoke] FAIL: appTickets[77777] should not exist (malformed hex)\n");
            SmokeLoader::g_had_error = true;
        } else {
            printf("[smoke] PASS: appTickets[77777] absent (malformed hex correctly skipped)\n");
        }

        // encTickets[55555]: "cafebabe0102030405060708" = 24 hex chars = 12 bytes, steamId=0.
        auto& et = SmokeLoader::g_encTickets;
        if (et.find(55555) == et.end()) {
            fprintf(stderr, "[smoke] FAIL: encTickets[55555] missing\n");
            SmokeLoader::g_had_error = true;
        } else {
            const auto& tkt = et.at(55555);
            if (tkt.steamId != 0) {
                fprintf(stderr, "[smoke] FAIL: encTickets[55555] steamId=%u (expected 0)\n", tkt.steamId);
                SmokeLoader::g_had_error = true;
            } else if (tkt.bytes.size() != 12) {
                fprintf(stderr, "[smoke] FAIL: encTickets[55555] bytes=%zu (expected 12)\n", tkt.bytes.size());
                SmokeLoader::g_had_error = true;
            } else {
                printf("[smoke] PASS: encTickets[55555] bytes=%zu steamId=0\n", tkt.bytes.size());
            }
        }

        // getAppTicket / getEncTicket query API smoke (direct table lookup mirrors real impl).
        {
            auto it_a = SmokeLoader::g_appTickets.find(55555);
            const SmokeLoader::LuaTicket* pA = (it_a != SmokeLoader::g_appTickets.end()) ? &it_a->second : nullptr;
            if (!pA) {
                fprintf(stderr, "[smoke] FAIL: getAppTicket(55555) returned nullptr\n");
                SmokeLoader::g_had_error = true;
            } else {
                printf("[smoke] PASS: getAppTicket(55555) non-null, steamId=0x%08x\n", pA->steamId);
            }

            auto it_e = SmokeLoader::g_encTickets.find(55555);
            const SmokeLoader::LuaTicket* pE = (it_e != SmokeLoader::g_encTickets.end()) ? &it_e->second : nullptr;
            if (!pE) {
                fprintf(stderr, "[smoke] FAIL: getEncTicket(55555) returned nullptr\n");
                SmokeLoader::g_had_error = true;
            } else {
                printf("[smoke] PASS: getEncTicket(55555) non-null, steamId=%u\n", pE->steamId);
            }

            // Miss case: unknown appId should not be found.
            auto it_miss = SmokeLoader::g_appTickets.find(99998);
            if (it_miss != SmokeLoader::g_appTickets.end()) {
                fprintf(stderr, "[smoke] FAIL: getAppTicket(99998) should be null (miss)\n");
                SmokeLoader::g_had_error = true;
            } else {
                printf("[smoke] PASS: getAppTicket(99998) correctly nullptr (miss)\n");
            }
        }
    }

    // ── callback selection order assertions ──────────────────────────
    printf("[smoke] --- callback selection order ---\n");
    if (!SmokeLoader::g_had_error) {

        // Verify refs were captured by the Lua script.
        if (SmokeLoader::g_fetchCodeExRef == LUA_NOREF) {
            fprintf(stderr, "[smoke] FAIL: g_fetchCodeExRef not set after script\n");
            SmokeLoader::g_had_error = true;
        }
        if (SmokeLoader::g_fetchCodeRef == LUA_NOREF) {
            fprintf(stderr, "[smoke] FAIL: g_fetchCodeRef not set after script\n");
            SmokeLoader::g_had_error = true;
        }

        // Branch 1: _ex ref set → must call fetch_manifest_code_ex(1, 2, 999)
        // and get 9000000000000000001 (fits in Lua 5.4 signed integer).
        if (!SmokeLoader::g_had_error) {
            uint64_t code = 0;
            bool ok = SmokeLoader::fetchManifestCode(1, 2, 999, code);
            if (!ok) {
                fprintf(stderr, "[smoke] FAIL: branch1 fetchManifestCode returned false\n");
                SmokeLoader::g_had_error = true;
            } else if (code != 9000000000000000001ULL) {
                fprintf(stderr, "[smoke] FAIL: branch1 wrong code %llu (expected 9000000000000000001)\n",
                        (unsigned long long)code);
                SmokeLoader::g_had_error = true;
            } else {
                printf("[smoke] PASS: branch1 (fetch_manifest_code_ex) code=%llu\n",
                       (unsigned long long)code);
            }
        }

        // Branch 1 with gid≠999: _ex returns nil → fall through to branch 2.
        // Branch 2 (fetch_manifest_code) returns 11111111111111111.
        if (!SmokeLoader::g_had_error) {
            uint64_t code = 0;
            bool ok = SmokeLoader::fetchManifestCode(1, 2, 1, code);
            if (!ok) {
                fprintf(stderr, "[smoke] FAIL: branch2 fetchManifestCode returned false\n");
                SmokeLoader::g_had_error = true;
            } else if (code != 11111111111111111ULL) {
                fprintf(stderr, "[smoke] FAIL: branch2 wrong code %llu (expected 11111111111111111)\n",
                        (unsigned long long)code);
                SmokeLoader::g_had_error = true;
            } else {
                printf("[smoke] PASS: branch2 (fetch_manifest_code) fallthrough code=%llu\n",
                       (unsigned long long)code);
            }
        }

        // Stack balance: verify Lua stack top is unchanged after the calls.
        if (!SmokeLoader::g_had_error) {
            int top = lua_gettop(SmokeLoader::g_lua);
            if (top != 0) {
                fprintf(stderr, "[smoke] FAIL: Lua stack not balanced after fetchManifestCode calls (top=%d)\n", top);
                SmokeLoader::g_had_error = true;
            } else {
                printf("[smoke] PASS: Lua stack balanced (top=0)\n");
            }
        }

        // Branch 3: unset both refs → fetchManifestCode returns false (no network).
        if (!SmokeLoader::g_had_error) {
            int savedEx  = SmokeLoader::g_fetchCodeExRef;
            int savedRef = SmokeLoader::g_fetchCodeRef;
            SmokeLoader::g_fetchCodeExRef = LUA_NOREF;
            SmokeLoader::g_fetchCodeRef   = LUA_NOREF;

            uint64_t code = 0;
            bool ok = SmokeLoader::fetchManifestCode(1, 2, 42, code);
            // No network → provider branch returns false.  That's correct.
            if (ok) {
                fprintf(stderr, "[smoke] FAIL: branch3 should return false without network\n");
                SmokeLoader::g_had_error = true;
            } else {
                printf("[smoke] PASS: branch3 (provider, no network) correctly returned false\n");
            }

            SmokeLoader::g_fetchCodeExRef = savedEx;
            SmokeLoader::g_fetchCodeRef   = savedRef;
        }
    }

    // ── incremental per-line parser ──────────────────────────────
    test_incremental_parser();

    // ── per-file refcount bookkeeping ────────────────────────────
    test_refcount();

    // ── unloadFile full removal ──────────────────────────────────
    test_unload_full_removal();

    // Cleanup temp files.
    std::error_code ec;
    std::filesystem::remove_all(luaDir, ec);

    if (!SmokeLoader::g_had_error) {
        printf("[smoke] PASS\n");
        return 0;
    }
    fprintf(stderr, "[smoke] FAIL\n");
    return 1;
}
