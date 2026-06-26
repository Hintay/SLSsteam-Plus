#include "rpc_engine.hpp"
#include "slssteam_messages.pb.h"

#include <cstdlib>
#include <string>
#include <vector>

namespace CloudSaves {

static constexpr int32_t kEResultOK = 1;

RpcEngine::RpcEngine(SaveStore& store, uint16_t httpPort)
    : m_store(store), m_port(httpPort) {}

void RpcEngine::setQuotaProvider(uint64_t (*fn)(uint32_t, uint32_t&)) { m_quotaFn = fn; }

bool RpcEngine::handle(const std::string& jobName, uint32_t appId, uint32_t accountId,
                       const std::string& reqBytes, std::string& respBytes, int32_t& eresult) {
    // jobName like "Cloud.GetAppFileChangelist#1" — match on the method segment.
    auto is = [&](const char* m) { return jobName.rfind(std::string("Cloud.") + m, 0) == 0; };
    if (is("GetAppFileChangelist"))  return handleChangelist(appId, accountId, reqBytes, respBytes, eresult);
    if (is("ClientBeginFileUpload")) return handleBeginUpload(appId, accountId, reqBytes, respBytes, eresult);
    if (is("ClientCommitFileUpload"))return handleCommitUpload(appId, accountId, reqBytes, respBytes, eresult);
    if (is("ClientFileDownload"))    return handleDownload(appId, accountId, reqBytes, respBytes, eresult);
    if (is("ClientDeleteFile"))      return handleDelete(appId, accountId, reqBytes, respBytes, eresult);
    if (is("GetAppQuotaUsage") || is("GetClientQuotaUsage"))
                                     return handleQuota(appId, accountId, reqBytes, respBytes, eresult);
    return false;
}

bool RpcEngine::handleChangelist(uint32_t appId, uint32_t accountId,
                                 const std::string& reqBytes, std::string& respBytes, int32_t& eresult) {
    (void)reqBytes;
    CCloud_GetAppFileChangelist_Response resp;
    eresult = kEResultOK;

    // Safety: empty store OR unresolved account -> is_only_delta=1 (never delete).
    auto files = (accountId != 0) ? m_store.list(accountId, appId) : std::vector<FileEntry>{};
    if (accountId == 0 || files.empty()) {
        resp.set_current_change_number(accountId ? m_store.changeNumber(accountId, appId) : 0);
        resp.set_is_only_delta(true);
        respBytes = resp.SerializeAsString();
        return true;
    }

    // Full manifest: list every file, is_only_delta=0.
    resp.set_current_change_number(m_store.changeNumber(accountId, appId));
    resp.set_is_only_delta(false);
    // path-prefix table: split each relPath into dir prefix + leaf.
    std::vector<std::string> prefixes;
    auto prefixIndex = [&](const std::string& dir) -> uint32_t {
        for (uint32_t i = 0; i < prefixes.size(); ++i) if (prefixes[i] == dir) return i;
        prefixes.push_back(dir);
        return static_cast<uint32_t>(prefixes.size() - 1);
    };
    for (const auto& fe : files) {
        size_t slash = fe.relPath.rfind('/');
        std::string dir = (slash == std::string::npos) ? "" : fe.relPath.substr(0, slash + 1);
        std::string leaf = (slash == std::string::npos) ? fe.relPath : fe.relPath.substr(slash + 1);
        auto* af = resp.add_files();
        af->set_file_name(leaf);
        // sha stored hex -> 20 raw bytes
        std::string raw;
        for (size_t i = 0; i + 1 < fe.shaHex.size(); i += 2)
            raw += static_cast<char>(std::strtol(fe.shaHex.substr(i, 2).c_str(), nullptr, 16));
        af->set_sha_file(raw);
        af->set_time_stamp(fe.timestamp);
        af->set_raw_file_size(static_cast<uint32_t>(fe.size));
        af->set_persist_state(0);          // Persisted
        af->set_platforms_to_sync(0xFFFFFFFFu);
        af->set_path_prefix_index(prefixIndex(dir));
    }
    for (auto& p : prefixes) resp.add_path_prefixes(p);
    respBytes = resp.SerializeAsString();
    return true;
}

bool RpcEngine::handleBeginUpload(uint32_t appId, uint32_t accountId,
                                  const std::string& reqBytes, std::string& respBytes, int32_t& eresult) {
    CCloud_ClientBeginFileUpload_Request req;
    if (!req.ParseFromString(reqBytes) || accountId == 0) { respBytes.clear(); eresult = 2; return true; }
    CCloud_ClientBeginFileUpload_Response resp;
    resp.set_encrypt_file(false);
    auto* blk = resp.add_block_requests();
    blk->set_url_host("127.0.0.1:" + std::to_string(m_port));
    blk->set_url_path("/" + std::to_string(accountId) + "/" + std::to_string(appId) +
                      "/" + req.filename());   // server url-decodes; leaf slashes ok
    blk->set_use_https(false);
    blk->set_http_method(4);  // PUT
    blk->set_block_offset(0);
    blk->set_block_length(req.has_file_size() ? req.file_size() : 0);
    respBytes = resp.SerializeAsString();
    eresult = kEResultOK;
    return true;
}

bool RpcEngine::handleCommitUpload(uint32_t appId, uint32_t accountId,
                                   const std::string& reqBytes, std::string& respBytes, int32_t& eresult) {
    CCloud_ClientCommitFileUpload_Request req;
    if (!req.ParseFromString(reqBytes) || accountId == 0) { respBytes.clear(); eresult = 2; return true; }
    bool ok = m_store.commit(accountId, appId, req.filename());
    CCloud_ClientCommitFileUpload_Response resp;
    resp.set_file_committed(ok);
    respBytes = resp.SerializeAsString();
    eresult = kEResultOK;
    return true;
}

bool RpcEngine::handleDownload(uint32_t appId, uint32_t accountId,
                               const std::string& reqBytes, std::string& respBytes, int32_t& eresult) {
    CCloud_ClientFileDownload_Request req;
    if (!req.ParseFromString(reqBytes) || accountId == 0) { respBytes.clear(); eresult = 2; return true; }
    std::vector<uint8_t> bytes;
    if (!m_store.read(accountId, appId, req.filename(), bytes)) { respBytes.clear(); eresult = 9; return true; } // FileNotFound
    CCloud_ClientFileDownload_Response resp;
    resp.set_file_size(static_cast<uint32_t>(bytes.size()));
    resp.set_raw_file_size(static_cast<uint32_t>(bytes.size()));
    resp.set_url_host("127.0.0.1:" + std::to_string(m_port));
    resp.set_url_path("/" + std::to_string(accountId) + "/" + std::to_string(appId) + "/" + req.filename());
    resp.set_use_https(false);
    respBytes = resp.SerializeAsString();
    eresult = kEResultOK;
    return true;
}

bool RpcEngine::handleDelete(uint32_t appId, uint32_t accountId,
                             const std::string& reqBytes, std::string& respBytes, int32_t& eresult) {
    CCloud_ClientDeleteFile_Request req;
    if (!req.ParseFromString(reqBytes) || accountId == 0) { respBytes.clear(); eresult = 2; return true; }
    m_store.remove(accountId, appId, req.filename());
    CCloud_ClientDeleteFile_Response resp;
    respBytes = resp.SerializeAsString();
    eresult = kEResultOK;
    return true;
}

bool RpcEngine::handleQuota(uint32_t appId, uint32_t accountId,
                            const std::string& reqBytes, std::string& respBytes, int32_t& eresult) {
    (void)reqBytes;
    uint64_t usedBytes = 0; uint64_t count = 0;
    if (accountId != 0)
        for (const auto& fe : m_store.list(accountId, appId)) { usedBytes += fe.size; ++count; }
    uint64_t maxBytes = 1073741824ULL;  // 1 GiB default
    uint32_t maxFiles = 10000;
    if (m_quotaFn) { uint32_t mf = 0; uint64_t q = m_quotaFn(appId, mf); if (q) { maxBytes = q; maxFiles = mf; } }
    CCloud_GetAppQuotaUsage_Response resp;
    resp.set_used_bytes(static_cast<uint32_t>(usedBytes));
    resp.set_total_bytes(static_cast<uint32_t>(maxBytes));
    resp.set_total_count(count);
    respBytes = resp.SerializeAsString();
    eresult = kEResultOK;
    return true;
}

}  // namespace CloudSaves
