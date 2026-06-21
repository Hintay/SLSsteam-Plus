#include "ManifestProvider.hpp"

#include "../config.hpp"
#include "../curl.hpp"
#include "../log.hpp"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace ManifestProvider
{

// ── Response parsers ────────────────────────────────────────────────────────

// Parse a plain decimal uint64 from the entire body (wudrm format).
static bool parsePlainUint(std::string_view body, uint64_t& out)
{
    // Trim leading/trailing whitespace to tolerate trailing newlines.
    const char* first = body.data();
    const char* last  = body.data() + body.size();
    while (first < last && (*first == ' ' || *first == '\t' ||
                            *first == '\r' || *first == '\n'))
        ++first;
    while (last > first && (last[-1] == ' ' || last[-1] == '\t' ||
                            last[-1] == '\r' || last[-1] == '\n'))
        --last;
    if (first == last) return false;

    // from_chars is bounded by [first, last): unlike strtoull it never scans past
    // the view, so it is safe on the non-null-terminated substring that
    // parseSteamRunJson hands in. Require the whole trimmed view to be consumed.
    uint64_t v = 0;
    const auto [end, ec] = std::from_chars(first, last, v, 10);
    if (ec != std::errc{} || end != last) return false;
    out = v;
    return true;
}

// Parse {"content":"<decimal_u64>"} JSON fragment (steam.run format).
// Minimal hand-rolled parse — no JSON library dependency.
static bool parseSteamRunJson(std::string_view body, uint64_t& out)
{
    // Find "content" key.
    size_t key = body.find("\"content\"");
    if (key == std::string_view::npos) return false;
    // Find the opening quote of the value.
    size_t q1 = body.find('"', key + 9);
    if (q1 == std::string_view::npos) return false;
    // Find the closing quote.
    size_t q2 = body.find('"', q1 + 1);
    if (q2 == std::string_view::npos) return false;
    return parsePlainUint(body.substr(q1 + 1, q2 - q1 - 1), out);
}

// ── Provider table ──────────────────────────────────────────────────────────

using Parser = bool (*)(std::string_view body, uint64_t& out);

struct Provider {
    const char* name;
    // URL template: contains exactly one "{gid}" placeholder.
    const char* urlTemplate;
    Parser      parse;
};

// Built-in providers: opensteamtool (default), wudrm, steamrun.
// NOTE: wudrm is plain HTTP and is the recommended provider for users in
// China; to force that endpoint without fallback, set `Manifest.Providers: wudrm`.
static const Provider kProviders[] = {
    { "opensteamtool", "https://manifest.opensteamtool.com/{gid}",      parsePlainUint    },
    // Plain HTTP is intentional: matches the provider's published endpoint URL.
    // The Steam chunk-hash check is the final integrity backstop; do NOT change to https
    // until the endpoint's https support has been verified.
    { "wudrm",         "http://gmrc.wudrm.com/manifest/{gid}",          parsePlainUint    },
    { "steamrun",      "https://manifest.steam.run/api/manifest/{gid}", parseSteamRunJson },
};

// The ordered fallback chain actually queried. Default = all built-ins in table order
// (opensteamtool -> wudrm -> steamrun). Set once at config load; guarded by g_chainMtx because a
// config hot-reload can rewrite it while async fetch workers read it.
static std::mutex                   g_chainMtx;
static std::vector<const Provider*> g_chain = { &kProviders[0], &kProviders[1], &kProviders[2] };

static std::vector<const Provider*> defaultChain()
{
    return { &kProviders[0], &kProviders[1], &kProviders[2] };
}

static const Provider* findProvider(const std::string& name)
{
    for (const auto& p : kProviders)
        if (name == p.name) return &p;
    return nullptr;
}

static std::vector<const Provider*> snapshotChain()
{
    std::lock_guard<std::mutex> lk(g_chainMtx);
    return g_chain;
}

static std::string chainSummary(const std::vector<const Provider*>& chain)
{
    std::string summary;
    for (size_t i = 0; i < chain.size(); ++i) { if (i) summary += " -> "; summary += chain[i]->name; }
    return summary;
}

// ── Public API ──────────────────────────────────────────────────────────────

void resetProviders()
{
    std::vector<const Provider*> chain = defaultChain();
    const std::string summary = chainSummary(chain);
    {
        std::lock_guard<std::mutex> lk(g_chainMtx);
        g_chain = std::move(chain);
    }
    g_pLog->info("ManifestProvider: provider chain = %s (default)\n", summary.c_str());
}

bool setProviders(const std::vector<std::string>& names)
{
    std::vector<const Provider*> chain;
    for (const auto& n : names) {
        const Provider* p = findProvider(n);
        if (!p) { g_pLog->warn("ManifestProvider: unknown provider '%s' in Providers list, skipping\n", n.c_str()); continue; }
        if (std::find(chain.begin(), chain.end(), p) != chain.end()) continue;   // dedup
        chain.push_back(p);
    }
    if (chain.empty()) {
        g_pLog->warn("ManifestProvider: Providers list had no valid entries, keeping current chain\n");
        return false;
    }
    const std::string summary = chainSummary(chain);
    {
        std::lock_guard<std::mutex> lk(g_chainMtx);
        g_chain = std::move(chain);
    }
    g_pLog->info("ManifestProvider: provider chain = %s\n", summary.c_str());
    return true;
}

const char* activeProviderName()
{
    std::lock_guard<std::mutex> lk(g_chainMtx);
    return g_chain.empty() ? kProviders[0].name : g_chain.front()->name;
}

std::string activeProviderChainSummary()
{
    std::lock_guard<std::mutex> lk(g_chainMtx);
    return chainSummary(g_chain.empty() ? defaultChain() : g_chain);
}

// Build the request URL by replacing the single "{gid}" token in the template.
static std::string buildUrl(const char* tmpl, uint64_t gid)
{
    std::string url;
    url.reserve(std::strlen(tmpl) + 24);
    const char* p = tmpl;
    while (*p) {
        if (p[0] == '{' && p[1] == 'g' && p[2] == 'i' && p[3] == 'd' && p[4] == '}') {
            char buf[24];
            std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(gid));
            url += buf;
            p += 5; // skip "{gid}"
        } else {
            url += *p++;
        }
    }
    return url;
}

// Query a single provider. Returns true + outCode only on a valid (non-zero) code; false on any
// failure — network/curl error, non-200 status (e.g. 403 from a blocked/unreachable endpoint),
// parse failure, or code==0 — so the caller can fall through to the next provider.
static bool tryProvider(const Provider& p, uint64_t gid, uint64_t& outCode)
{
    const std::string url = buildUrl(p.urlTemplate, gid);

    Curl::RequestOptions options;
    options.timeoutConnectMs = g_config.manifestTimeoutConnectMs.get();
    options.timeoutTotalMs = g_config.manifestTimeoutTotalMs.get();
    options.reuseConnection = g_config.manifestReuseConnection.get();

    std::string body;
    long        status = 0;
    static const std::string noBody;

    std::vector<std::pair<std::string, std::string>> headers;
    if (url.find("opensteamtool.com") != std::string::npos)
        headers.push_back({"User-Agent", "OpenSteamTool/1.0"});

    int rc = Curl::request("GET", url.c_str(), headers, noBody, body, status, options);

    g_pLog->info("ManifestProvider: provider='%s' gid=%llu curlrc=%d status=%ld reuse=%i\n",
                 p.name, static_cast<unsigned long long>(gid), rc, status,
                 options.reuseConnection);

    if (rc != 0 || status != 200) return false;

    uint64_t code = 0;
    if (!p.parse(body, code)) {
        g_pLog->warn("ManifestProvider: provider='%s' failed to parse response body (len=%zu)\n", p.name, body.size());
        return false;
    }
    if (code == 0) {
        g_pLog->warn("ManifestProvider: provider='%s' returned code=0, rejecting\n", p.name);
        return false;
    }

    outCode = code;
    return true;
}

// Fetch a manifest code with provider fallback: try each configured provider in order until one
// yields a valid code. A provider that 403s / is unreachable / lacks the gid no longer dead-ends
// the whole fetch. Read-only over the global state, so it is safe to call from concurrent async
// fetch workers.
bool fetchFromProvider(uint64_t gid, uint64_t& outCode)
{
    const std::vector<const Provider*> chain = snapshotChain();

    for (size_t i = 0; i < chain.size(); ++i) {
        if (tryProvider(*chain[i], gid, outCode)) {
            if (i > 0)
                g_pLog->info("ManifestProvider: fell back to '%s' (#%zu in chain) for gid=%llu\n",
                             chain[i]->name, i + 1, static_cast<unsigned long long>(gid));
            return true;
        }
    }

    // once() (not warn): dedups per gid via the message text and does not pop a critical notify —
    // the single user-facing prompt is RequestCode's per-gid denial warn.
    g_pLog->once("ManifestProvider: all %zu provider(s) in chain failed for gid=%llu\n",
                 chain.size(), static_cast<unsigned long long>(gid));
    return false;
}

} // namespace ManifestProvider
