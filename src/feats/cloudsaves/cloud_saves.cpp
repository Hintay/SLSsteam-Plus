#include "cloud_saves.hpp"
#include "rpc_engine.hpp"
#include "save_store.hpp"
#include "http_transfer.hpp"
#include "appinfo_kv.hpp"

#include "../../config.hpp"
#include "../../ownership.hpp"
#include "../../sdk/RawNetPacket.hpp"
#include "../../sdk/IClientApps.hpp"
#include "../../sdk/CProtoBufMsgBase.hpp"   // EMSG_* enum values
#include "../../sdk/CNetPacket.hpp"         // kMsgHdrProtoFlag
#include "../../log.hpp"

#include "slssteam_messages.pb.h"           // CMsgProtoBufHeader

#include <atomic>
#include <cstdlib>
#include <deque>
#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace CloudSaves {

namespace {
std::unique_ptr<SaveStore>    g_store;
std::unique_ptr<HttpTransfer> g_http;
std::unique_ptr<RpcEngine>    g_engine;
std::atomic<uint32_t>         g_accountId{0};

std::mutex                        g_qmtx;
std::deque<std::vector<uint8_t>>  g_queue;   // ready 147 response packets
std::atomic<size_t>               g_qcount{0};

std::string defaultStoreRoot() {
    const char* home = ::getenv("HOME");
    std::string base = (home && home[0]) ? std::string(home) : "/tmp";
    return base + "/.local/share/SLSsteam/cloudsaves";
}

// Fetch one appinfo section into `out` for the given serialization form.
// Returns the byte count (>0), or 0 on failure. Grows the buffer if the section
// did not fit in the initial stack buffer.
int32_t fetchAppDataSection(uint32_t appId, EAppInfoSection section,
                            bool bSharedKVSymbols, std::vector<char>& out) {
    char stackBuf[8192];
    int32_t n = g_pClientApps->getAppDataSection(
        appId, section, stackBuf, sizeof(stackBuf), bSharedKVSymbols);
    if (n <= 0) return 0;
    if (static_cast<uint32_t>(n) <= sizeof(stackBuf)) {
        out.assign(stackBuf, stackBuf + n);
        return n;
    }
    out.resize(static_cast<size_t>(n));
    int32_t n2 = g_pClientApps->getAppDataSection(
        appId, section, out.data(), static_cast<uint32_t>(out.size()), bSharedKVSymbols);
    if (n2 <= 0) return 0;
    out.resize(static_cast<size_t>(n2));
    return n2;
}

// Hex preview of the first bytes, for format diagnosis in the debug log.
std::string hexHead(const std::vector<char>& b, size_t maxBytes = 24) {
    static const char* hx = "0123456789abcdef";
    std::string s;
    size_t lim = b.size() < maxBytes ? b.size() : maxBytes;
    for (size_t i = 0; i < lim; ++i) {
        uint8_t c = static_cast<uint8_t>(b[i]);
        s.push_back(hx[c >> 4]); s.push_back(hx[c & 0xF]); s.push_back(' ');
    }
    return s;
}

// Read the developer's real ufs.quota / maxnumfiles from appinfo. Returns the
// quota in bytes (with outMaxFiles set), or 0 if unavailable — in which case the
// RpcEngine falls back to its default quota. Fail-closed by design: any read or
// parse failure simply yields 0, never a wrong non-zero value.
//
// We do not yet know which bSharedKVSymbols value Steam maps to the parseable
// inline-string form (the pooled-symbol form is not parseable out of process),
// so for now we try BOTH and use whichever parses. Each attempt logs its flag,
// byte count, parse result, and a byte preview, so the on-device debug log shows
// which branch wins. TODO: once confirmed on-device, delete the losing branch
// and keep the single correct getAppDataSection() call.
uint64_t readUfsQuota(uint32_t appId, uint32_t& outMaxFiles) {
    outMaxFiles = 0;
    if (!g_pClientApps) return 0;

    for (int attempt = 0; attempt < 2; ++attempt) {
        const bool shared = (attempt == 1);   // try false first, then true
        std::vector<char> buf;
        int32_t n = fetchAppDataSection(appId, APPINFOSECTION_UFS, shared, buf);
        if (n <= 0) {
            g_pLog->debug("CloudSaves: UFS fetch app=%u shared=%d -> n=%d (skip)\n",
                          appId, shared ? 1 : 0, n);
            continue;
        }
        uint64_t quota = 0; uint32_t maxFiles = 0;
        bool ok = ParseUfsQuota(reinterpret_cast<const uint8_t*>(buf.data()),
                                static_cast<size_t>(n), quota, maxFiles);
        g_pLog->debug("CloudSaves: UFS attempt app=%u shared=%d n=%d parse=%d "
                      "quota=%llu maxfiles=%u head=[%s]\n",
                      appId, shared ? 1 : 0, n, ok ? 1 : 0,
                      static_cast<unsigned long long>(quota), maxFiles,
                      hexHead(buf).c_str());
        if (ok) {
            outMaxFiles = maxFiles;
            return quota;
        }
    }
    return 0;
}
}  // namespace

void init() {
    try {
        std::string root = g_config.cloudStorePath.get();
        if (root.empty()) root = defaultStoreRoot();
        g_store = std::make_unique<SaveStore>(root);
        g_store->sweepStaging();
        g_http = std::make_unique<HttpTransfer>(*g_store);
        if (!g_http->start()) {
            g_pLog->warn("CloudSaves: HTTP transfer failed to start; redirection disabled\n");
            g_http.reset();
            return;
        }
        g_engine = std::make_unique<RpcEngine>(*g_store, g_http->port());
        g_engine->setQuotaProvider(&readUfsQuota);
        g_pLog->info("CloudSaves: initialized, store=%s\n", root.c_str());
    } catch (const std::exception& e) {
        g_pLog->warn("CloudSaves: init failed: %s\n", e.what());
    } catch (...) {
        g_pLog->warn("CloudSaves: init failed (unknown)\n");
    }
}

void shutdown() {
    if (g_http) g_http->stop();
    g_engine.reset(); g_http.reset(); g_store.reset();
}

void setAccountId(uint32_t accountId) { g_accountId.store(accountId, std::memory_order_release); }

bool handlesApp(uint32_t appId) {
    return g_config.cloudMode.get() == CloudMode::Redirect && Ownership::isControlledApp(appId);
}

bool onSendFrame(const uint8_t* pubData, uint32_t cubData) {
    if (!g_engine) return false;
    uint16_t eMsg = 0;
    const uint8_t *pHdr = nullptr, *pBody = nullptr;
    uint32_t cbHdr = 0, cbBody = 0;
    if (!netpacket::UnpackRaw(pubData, cubData, eMsg, pHdr, cbHdr, pBody, cbBody)) return false;
    if (eMsg != EMSG_SERVICE_METHOD_CALL_FROM_CLIENT) return false;

    CMsgProtoBufHeader hdr;
    if (!hdr.ParseFromArray(pHdr, static_cast<int>(cbHdr))) return false;
    if (!hdr.has_target_job_name()) return false;
    const std::string& job = hdr.target_job_name();
    if (job.rfind("Cloud.", 0) != 0) return false;          // not a cloud RPC
    if (!hdr.has_jobid_source()) return false;

    // appid is field 1 of every Cloud.* request (field 2 for CommitFileUpload).
    // Re-parse minimally via the engine's typed handlers — but we need appId now
    // for the handlesApp gate. Extract appId with a tiny varint field read.
    uint32_t appId = 0;
    {
        // top-level field 1 (or field 2 for commit), wire type 0 (varint)
        uint32_t want = (job.rfind("Cloud.ClientCommitFileUpload", 0) == 0) ? 2u : 1u;
        const uint8_t* p = pBody; const uint8_t* end = pBody + cbBody;
        while (p < end) {
            uint64_t tag = 0; int shift = 0;
            while (p < end) { uint8_t b = *p++; tag |= uint64_t(b & 0x7F) << shift; if (!(b & 0x80)) break; shift += 7; }
            uint32_t field = static_cast<uint32_t>(tag >> 3); uint32_t wt = static_cast<uint32_t>(tag & 7);
            if (field == want && wt == 0) {
                uint64_t v = 0; shift = 0;
                while (p < end) { uint8_t b = *p++; v |= uint64_t(b & 0x7F) << shift; if (!(b & 0x80)) break; shift += 7; }
                appId = static_cast<uint32_t>(v); break;
            }
            // skip other fields
            if (wt == 0) { while (p < end && (*p & 0x80)) ++p; if (p < end) ++p; }
            else if (wt == 2) { uint64_t len = 0; int s = 0; while (p < end) { uint8_t b=*p++; len|=uint64_t(b&0x7F)<<s; if(!(b&0x80))break; s+=7;} p += len; }
            else if (wt == 1) p += 8;
            else if (wt == 5) p += 4;
            else break;
        }
    }
    if (!appId || !handlesApp(appId)) return false;

    const uint32_t accountId = g_accountId.load(std::memory_order_acquire);
    std::string reqBytes(reinterpret_cast<const char*>(pBody), cbBody);
    std::string respBody; int32_t eresult = 2;
    if (!g_engine->handle(job, appId, accountId, reqBytes, respBody, eresult)) return false;

    // Build the 147 ServiceMethodResponse correlated to this job.
    // Mirror RequestCode::buildInject: derive the response header from the request's
    // own header so any echoed routing fields the CM normally returns (steamid,
    // client_sessionid, realm, etc.) are preserved. Copy first so we don't mutate the
    // request header `hdr` we still read from above. Then: jobid_target = request's
    // jobid_source, clear jobid_source, set eresult, keep target_job_name.
    CMsgProtoBufHeader respHdr = hdr;
    respHdr.set_jobid_target(hdr.jobid_source());
    respHdr.clear_jobid_source();
    respHdr.set_eresult(eresult);
    respHdr.set_target_job_name(job);
    std::string respHdrBytes = respHdr.SerializeAsString();

    std::vector<uint8_t> pkt;
    const uint8_t* outData = nullptr; uint32_t outSize = 0;
    if (!netpacket::AssembleRaw(pkt,
            static_cast<uint32_t>(EMSG_SERVICE_METHOD_RESPONSE) | kMsgHdrProtoFlag,
            respHdrBytes.data(), respHdrBytes.size(),
            respBody.data(), respBody.size(), outData, outSize)) {
        g_pLog->warn("CloudSaves: failed to assemble response for %s\n", job.c_str());
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(g_qmtx);
        if (g_queue.size() < 128) g_queue.emplace_back(outData, outData + outSize);
        g_qcount.store(g_queue.size(), std::memory_order_release);
    }
    g_pLog->debug("CloudSaves: handled %s app=%u acct=%u -> queued %u-byte resp (e=%d)\n",
                  job.c_str(), appId, accountId, outSize, eresult);
    return true;  // DROP outbound frame
}

bool nextInjection(const uint8_t*& outData, uint32_t& outSize) {
    if (g_qcount.load(std::memory_order_acquire) == 0) return false;
    static thread_local std::vector<uint8_t> hold;
    {
        std::lock_guard<std::mutex> lk(g_qmtx);
        if (g_queue.empty()) return false;
        hold = std::move(g_queue.front());
        g_queue.pop_front();
        g_qcount.store(g_queue.size(), std::memory_order_release);
    }
    outData = hold.data();
    outSize = static_cast<uint32_t>(hold.size());
    return true;
}

}  // namespace CloudSaves
