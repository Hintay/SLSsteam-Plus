#include "cloud_saves.hpp"
#include "rpc_engine.hpp"
#include "save_store.hpp"
#include "http_transfer.hpp"

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

// Read official ufs.quota from appinfo. Returns 0 if unavailable.
uint64_t readUfsQuota(uint32_t appId, uint32_t& outMaxFiles) {
    outMaxFiles = 0;
    if (!g_pClientApps) return 0;
    char buf[8192];
    int32_t n = g_pClientApps->getAppDataSection(appId, APPINFOSECTION_UFS, buf, sizeof(buf));
    if (n <= 0) return 0;
    // appinfo UFS is a binary KV blob; scan for "quota"/"maxnumfiles" values.
    // Conservative: if parsing is uncertain, return 0 (RpcEngine falls back).
    // (Binary-KV parse implemented in Task 5.x if needed; v1 may return 0 and use
    //  the 1 GiB default — documented limitation.)
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
