#pragma once
#include "save_store.hpp"
#include <cstdint>
#include <string>

namespace CloudSaves {

class RpcEngine {
public:
    RpcEngine(SaveStore& store, uint16_t httpPort);

    // Dispatch one Cloud.* service method. jobName is the target_job_name
    // ("Cloud.GetAppFileChangelist#1", "Cloud.ClientBeginFileUpload#1", ...).
    // Returns true if handled (respBytes + eresult are set). false => not ours.
    bool handle(const std::string& jobName, uint32_t appId, uint32_t accountId,
                const std::string& reqBytes, std::string& respBytes, int32_t& eresult);

    // Quota source: real ufs.quota from appinfo. Settable so tests can stub it.
    // bytes==0 => fall back to defaults (1 GiB / 10000 files).
    void setQuotaProvider(uint64_t (*fn)(uint32_t appId, uint32_t& outMaxFiles));

private:
    bool handleChangelist(uint32_t appId, uint32_t accountId,
                          const std::string& reqBytes, std::string& respBytes, int32_t& eresult);
    bool handleBeginUpload(uint32_t appId, uint32_t accountId,
                           const std::string& reqBytes, std::string& respBytes, int32_t& eresult);
    bool handleCommitUpload(uint32_t appId, uint32_t accountId,
                            const std::string& reqBytes, std::string& respBytes, int32_t& eresult);
    bool handleDownload(uint32_t appId, uint32_t accountId,
                        const std::string& reqBytes, std::string& respBytes, int32_t& eresult);
    bool handleDelete(uint32_t appId, uint32_t accountId,
                      const std::string& reqBytes, std::string& respBytes, int32_t& eresult);
    bool handleQuota(uint32_t appId, uint32_t accountId,
                     const std::string& reqBytes, std::string& respBytes, int32_t& eresult);

    SaveStore& m_store;
    uint16_t   m_port;
    uint64_t (*m_quotaFn)(uint32_t, uint32_t&) = nullptr;
};

}  // namespace CloudSaves
