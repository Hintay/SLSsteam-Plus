// Standalone smoke tests for the Cloud Saves pure units (SaveStore, RpcEngine).
// No Steam, no protobuf-linked SLSsteam types beyond the generated cloud messages.
// Build: make bin/cloudsaves_smoke && ./bin/cloudsaves_smoke
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string>
#include <filesystem>
#include <vector>

#include "feats/cloudsaves/sha1.hpp"
#include "feats/cloudsaves/manifest.hpp"
#include "feats/cloudsaves/save_store.hpp"
#include "feats/cloudsaves/peer_check.hpp"
#include "feats/cloudsaves/appinfo_kv.hpp"
#include "slssteam_messages.pb.h"
#include "feats/cloudsaves/rpc_engine.hpp"
#include "feats/cloudsaves/cloud_ui_reveal.hpp"

static int g_failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); ++g_failures; } } while (0)

static void test_manifest_roundtrip() {
    CloudSaves::Manifest m;
    m.changeNumber = 7;
    m.files["save/slot0.dat"] = {"save/slot0.dat", "a9993e364706816aba3e25717850c26c9cd0d89d", 3, 1719000000};
    std::string text = CloudSaves::SerializeManifest(m);

    CloudSaves::Manifest parsed;
    CHECK(CloudSaves::ParseManifest(text, parsed));
    CHECK(parsed.changeNumber == 7);
    CHECK(parsed.files.size() == 1);
    CHECK(parsed.files.at("save/slot0.dat").size == 3);
    CHECK(parsed.files.at("save/slot0.dat").shaHex == "a9993e364706816aba3e25717850c26c9cd0d89d");
}

static void test_sha1_known_vectors() {
    // RFC 3174 / well-known vectors
    CHECK(CloudSaves::Sha1Hex(reinterpret_cast<const uint8_t*>(""), 0)
          == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    const char* abc = "abc";
    CHECK(CloudSaves::Sha1Hex(reinterpret_cast<const uint8_t*>(abc), 3)
          == "a9993e364706816aba3e25717850c26c9cd0d89d");
}

static void test_savestore_write_read_delete() {
    std::string root = "/tmp/sls_cloudsaves_test";
    std::filesystem::remove_all(root);
    CloudSaves::SaveStore store(root);

    // begin staging, write bytes there, commit
    std::string staging = store.beginStaging(123, 480, "save/slot0.dat");
    CHECK(!staging.empty());
    {
        FILE* f = std::fopen(staging.c_str(), "wb");
        CHECK(f != nullptr);
        const char* data = "hello";
        std::fwrite(data, 1, 5, f);
        std::fclose(f);
    }
    CHECK(store.commit(123, 480, "save/slot0.dat", /*timestamp=*/1700000000));

    // change_number is content-derived: the max file timestamp.
    CHECK(store.changeNumber(123, 480) == 1700000000ull);
    CHECK(store.isComplete(123, 480));

    // read back (SHA-verified internally)
    std::vector<uint8_t> out;
    CHECK(store.read(123, 480, "save/slot0.dat", out));
    CHECK(out.size() == 5);
    CHECK(std::string(out.begin(), out.end()) == "hello");

    // list reflects it with sha of "hello"
    auto files = store.list(123, 480);
    CHECK(files.size() == 1);
    CHECK(files[0].relPath == "save/slot0.dat");
    CHECK(files[0].size == 5);
    CHECK(files[0].timestamp == 1700000000ull);
    CHECK(files[0].shaHex == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"); // sha1("hello")

    // delete removes file; change_number drops back to 0 (no files left)
    CHECK(store.remove(123, 480, "save/slot0.dat"));
    CHECK(store.changeNumber(123, 480) == 0);
    std::vector<uint8_t> gone;
    CHECK(!store.read(123, 480, "save/slot0.dat", gone));
}

static void test_savestore_manifest_persists() {
    std::string root = "/tmp/sls_cloudsaves_test2";
    std::filesystem::remove_all(root);
    {
        CloudSaves::SaveStore store(root);
        std::string s = store.beginStaging(1, 2, "a.dat");
        FILE* f = std::fopen(s.c_str(), "wb"); std::fwrite("x", 1, 1, f); std::fclose(f);
        store.commit(1, 2, "a.dat", /*timestamp=*/1700000123);
    }
    // New instance reads persisted manifest
    CloudSaves::SaveStore store2(root);
    CHECK(store2.changeNumber(1, 2) == 1700000123ull);
    auto files = store2.list(1, 2);
    CHECK(files.size() == 1);
}

static void test_proctcp_parse() {
    // local_address is hex IP:PORT. 0100007F:1F90 = 127.0.0.1:8080, inode in col 9.
    std::string line =
      "   0: 0100007F:1F90 0100007F:E4C2 01 00000000:00000000 00:00000000 00000000  1000  0 654321 1 ...";
    uint16_t localPort = 0; uint64_t inode = 0;
    CHECK(CloudSaves::ParseProcTcpLine(line, localPort, inode));
    CHECK(localPort == 0x1F90);
    CHECK(inode == 654321);
}

static void test_changelist_empty_is_delta() {
    std::filesystem::remove_all("/tmp/sls_cs_rpc");
    CloudSaves::SaveStore store("/tmp/sls_cs_rpc");
    CloudSaves::RpcEngine eng(store, /*httpPort=*/12345);

    CCloud_GetAppFileChangelist_Request req;
    req.set_appid(480);
    req.set_synced_change_number(0);
    std::string reqBytes = req.SerializeAsString();

    std::string respBytes; int32_t eresult = 0;
    CHECK(eng.handle("Cloud.GetAppFileChangelist#1", 480, /*accountId=*/777,
                     reqBytes, respBytes, eresult));
    CHECK(eresult == 1);  // k_EResultOK

    CCloud_GetAppFileChangelist_Response resp;
    CHECK(resp.ParseFromString(respBytes));
    // Empty store -> is_only_delta must be true (never delete local saves)
    CHECK(resp.is_only_delta() == true);
    CHECK(resp.files_size() == 0);
    CHECK(resp.current_change_number() == 0);
}

static void test_changelist_unresolved_account_is_delta() {
    CloudSaves::SaveStore store("/tmp/sls_cs_rpc2");
    CloudSaves::RpcEngine eng(store, 12345);
    CCloud_GetAppFileChangelist_Request req; req.set_appid(480);
    std::string respBytes; int32_t eresult = 0;
    CHECK(eng.handle("Cloud.GetAppFileChangelist#1", 480, /*accountId=*/0,
                     req.SerializeAsString(), respBytes, eresult));
    CCloud_GetAppFileChangelist_Response resp;
    CHECK(resp.ParseFromString(respBytes));
    CHECK(resp.is_only_delta() == true);  // accountId unresolved -> safe delta
}

static void test_upload_commit_download_cycle() {
    std::filesystem::remove_all("/tmp/sls_cs_cycle");
    CloudSaves::SaveStore store("/tmp/sls_cs_cycle");
    CloudSaves::RpcEngine eng(store, 23456);

    // BeginUpload -> response carries a PUT URL at our port
    CCloud_ClientBeginFileUpload_Request beg;
    beg.set_appid(480); beg.set_filename("save/a.dat"); beg.set_file_size(5);
    beg.set_time_stamp(1700001234);  // Steam's authoritative save time
    std::string respBytes; int32_t e = 0;
    CHECK(eng.handle("Cloud.ClientBeginFileUpload#1", 480, 777, beg.SerializeAsString(), respBytes, e));
    CHECK(e == 1);
    CCloud_ClientBeginFileUpload_Response begResp;
    CHECK(begResp.ParseFromString(respBytes));
    CHECK(begResp.block_requests_size() == 1);
    CHECK(begResp.block_requests(0).url_host() == "127.0.0.1:23456");
    CHECK(begResp.block_requests(0).http_method() == 4);  // PUT
    CHECK(begResp.block_requests(0).use_https() == false);

    // Simulate the HTTP PUT by staging+writing the bytes ourselves
    std::string staging = store.beginStaging(777, 480, "save/a.dat");
    { FILE* f = std::fopen(staging.c_str(), "wb"); std::fwrite("hello", 1, 5, f); std::fclose(f); }

    // CommitUpload -> finalizes
    CCloud_ClientCommitFileUpload_Request com;
    com.set_appid(480); com.set_filename("save/a.dat"); com.set_transfer_succeeded(true);
    CHECK(eng.handle("Cloud.ClientCommitFileUpload#1", 480, 777, com.SerializeAsString(), respBytes, e));
    CCloud_ClientCommitFileUpload_Response comResp;
    CHECK(comResp.ParseFromString(respBytes));
    CHECK(comResp.file_committed() == true);
    CHECK(store.changeNumber(777, 480) == 1700001234ull);  // commit recorded Steam's timestamp

    // Changelist now full (is_only_delta=0, 1 file)
    CCloud_GetAppFileChangelist_Request cl; cl.set_appid(480);
    CHECK(eng.handle("Cloud.GetAppFileChangelist#1", 480, 777, cl.SerializeAsString(), respBytes, e));
    CCloud_GetAppFileChangelist_Response clResp; clResp.ParseFromString(respBytes);
    CHECK(clResp.is_only_delta() == false);
    CHECK(clResp.files_size() == 1);
    CHECK(clResp.files(0).file_name() == "a.dat");
    CHECK(clResp.path_prefixes_size() == 1);
    CHECK(clResp.path_prefixes(0) == "save/");

    // Download -> GET URL
    CCloud_ClientFileDownload_Request dl; dl.set_appid(480); dl.set_filename("save/a.dat");
    CHECK(eng.handle("Cloud.ClientFileDownload#1", 480, 777, dl.SerializeAsString(), respBytes, e));
    CCloud_ClientFileDownload_Response dlResp; dlResp.ParseFromString(respBytes);
    CHECK(dlResp.url_host() == "127.0.0.1:23456");
    CHECK(dlResp.file_size() == 5);
    CHECK(dlResp.time_stamp() == 1700001234ull);            // echoed for newest-wins
    CHECK(dlResp.sha_file().size() == 20);                  // 20-byte SHA-1 echoed

    // Delete
    CCloud_ClientDeleteFile_Request del; del.set_appid(480); del.set_filename("save/a.dat");
    CHECK(eng.handle("Cloud.ClientDeleteFile#1", 480, 777, del.SerializeAsString(), respBytes, e));
    CHECK(store.changeNumber(777, 480) == 0);  // last file gone -> derived CN back to 0
}

// ---- Model E: completeness gate + read integrity (multi-machine safety) ----
static void test_savestore_completeness_and_integrity() {
    std::string root = "/tmp/sls_cs_complete";
    std::filesystem::remove_all(root);
    CloudSaves::SaveStore store(root);
    std::string s = store.beginStaging(5, 9, "d/f.dat");
    { FILE* f = std::fopen(s.c_str(), "wb"); std::fwrite("abc", 1, 3, f); std::fclose(f); }
    CHECK(store.commit(5, 9, "d/f.dat", 1700000000));
    CHECK(store.isComplete(5, 9));

    const std::string onDisk = root + "/5/9/files/d/f.dat";

    // Corrupted bytes (partial sync): size/SHA disagree with manifest -> refuse to serve.
    { FILE* f = std::fopen(onDisk.c_str(), "wb"); std::fwrite("XYZ!", 1, 4, f); std::fclose(f); }
    std::vector<uint8_t> out;
    CHECK(!store.read(5, 9, "d/f.dat", out));
    CHECK(!store.isComplete(5, 9));            // size mismatch -> incomplete

    // Missing file (mid-sync): manifest knows it, disk doesn't -> incomplete, no serve.
    std::filesystem::remove(onDisk);
    CHECK(!store.isComplete(5, 9));
    std::vector<uint8_t> out2;
    CHECK(!store.read(5, 9, "d/f.dat", out2));
}

static void test_changelist_incomplete_is_delta() {
    std::filesystem::remove_all("/tmp/sls_cs_incpl");
    CloudSaves::SaveStore store("/tmp/sls_cs_incpl");
    CloudSaves::RpcEngine eng(store, 34567);
    std::string s = store.beginStaging(7, 11, "x.dat");
    { FILE* f = std::fopen(s.c_str(), "wb"); std::fwrite("data", 1, 4, f); std::fclose(f); }
    CHECK(store.commit(7, 11, "x.dat", 1700000000));

    CCloud_GetAppFileChangelist_Request cl; cl.set_appid(11);
    std::string respBytes; int32_t e = 0;

    // Complete store -> authoritative full list (is_only_delta=0).
    CHECK(eng.handle("Cloud.GetAppFileChangelist#1", 11, 7, cl.SerializeAsString(), respBytes, e));
    CCloud_GetAppFileChangelist_Response r1; r1.ParseFromString(respBytes);
    CHECK(r1.is_only_delta() == false);
    CHECK(r1.files_size() == 1);

    // Mid-sync: the on-disk file is gone but the manifest still lists it. Must NOT
    // present as authoritative, else Steam would treat it as a deletion.
    std::filesystem::remove("/tmp/sls_cs_incpl/7/11/files/x.dat");
    CHECK(eng.handle("Cloud.GetAppFileChangelist#1", 11, 7, cl.SerializeAsString(), respBytes, e));
    CCloud_GetAppFileChangelist_Response r2; r2.ParseFromString(respBytes);
    CHECK(r2.is_only_delta() == true);
}

// ---- binary-KV (appinfo UFS) quota parsing -------------------------------
// Tiny builder for Steam's standard binary KeyValues form (inline string keys).
namespace bkv {
static void key(std::vector<uint8_t>& b, uint8_t type, const char* name) {
    b.push_back(type);
    for (const char* p = name; *p; ++p) b.push_back((uint8_t)*p);
    b.push_back(0);
}
static void subtreeBegin(std::vector<uint8_t>& b, const char* name) { key(b, 0, name); }
static void end(std::vector<uint8_t>& b) { b.push_back(8); }
static void i32(std::vector<uint8_t>& b, const char* name, uint32_t v) {
    key(b, 2, name);
    for (int i = 0; i < 4; ++i) b.push_back((uint8_t)((v >> (8 * i)) & 0xFF));
}
static void u64(std::vector<uint8_t>& b, const char* name, uint64_t v) {
    key(b, 7, name);
    for (int i = 0; i < 8; ++i) b.push_back((uint8_t)((v >> (8 * i)) & 0xFF));
}
static void str(std::vector<uint8_t>& b, const char* name, const char* v) {
    key(b, 1, name);
    for (const char* p = v; *p; ++p) b.push_back((uint8_t)*p);
    b.push_back(0);
}
}  // namespace bkv

static void test_ufs_quota_typed_int() {
    // ufs { quota=104857600 (i32), maxnumfiles=1000 (i32) }
    std::vector<uint8_t> b;
    bkv::subtreeBegin(b, "ufs");
    bkv::i32(b, "quota", 104857600u);
    bkv::i32(b, "maxnumfiles", 1000u);
    bkv::end(b);  // ufs
    uint64_t q = 0; uint32_t f = 0;
    CHECK(CloudSaves::ParseUfsQuota(b.data(), b.size(), q, f));
    CHECK(q == 104857600u);
    CHECK(f == 1000u);
}

static void test_ufs_quota_string_values() {
    // numeric values stored as strings must still parse
    std::vector<uint8_t> b;
    bkv::subtreeBegin(b, "ufs");
    bkv::str(b, "quota", "536870912");
    bkv::str(b, "maxnumfiles", "256");
    bkv::end(b);
    uint64_t q = 0; uint32_t f = 0;
    CHECK(CloudSaves::ParseUfsQuota(b.data(), b.size(), q, f));
    CHECK(q == 536870912u);
    CHECK(f == 256u);
}

static void test_ufs_quota_uint64_and_nested() {
    // quota as UInt64, plus an unrelated nested savefiles subtree before it
    std::vector<uint8_t> b;
    bkv::subtreeBegin(b, "ufs");
    bkv::subtreeBegin(b, "savefiles");
      bkv::subtreeBegin(b, "0");
        bkv::str(b, "root", "gameroot");
        bkv::str(b, "path", "saves");
      bkv::end(b);
    bkv::end(b);  // savefiles
    bkv::u64(b, "quota", 3221225472ULL);  // 3 GiB, needs 64-bit
    bkv::i32(b, "maxnumfiles", 2000u);
    bkv::end(b);  // ufs
    uint64_t q = 0; uint32_t f = 0;
    CHECK(CloudSaves::ParseUfsQuota(b.data(), b.size(), q, f));
    CHECK(q == 3221225472ULL);
    CHECK(f == 2000u);
}

static void test_ufs_quota_missing_field_fails() {
    std::vector<uint8_t> b;
    bkv::subtreeBegin(b, "ufs");
    bkv::i32(b, "quota", 1048576u);   // no maxnumfiles
    bkv::end(b);
    uint64_t q = 1; uint32_t f = 1;
    CHECK(!CloudSaves::ParseUfsQuota(b.data(), b.size(), q, f));
    CHECK(q == 0);  // outputs cleared on failure
    CHECK(f == 0);
}

static void test_ufs_quota_implausible_fails() {
    std::vector<uint8_t> b;
    bkv::subtreeBegin(b, "ufs");
    bkv::u64(b, "quota", 0xFFFFFFFFFFFFFFFFULL);  // way over 1 TiB
    bkv::i32(b, "maxnumfiles", 1000u);
    bkv::end(b);
    uint64_t q = 0; uint32_t f = 0;
    CHECK(!CloudSaves::ParseUfsQuota(b.data(), b.size(), q, f));
}

static void test_ufs_quota_zero_fails_and_truncation_safe() {
    // zero quota is not usable
    std::vector<uint8_t> b;
    bkv::subtreeBegin(b, "ufs");
    bkv::i32(b, "quota", 0u);
    bkv::i32(b, "maxnumfiles", 1000u);
    bkv::end(b);
    uint64_t q = 0; uint32_t f = 0;
    CHECK(!CloudSaves::ParseUfsQuota(b.data(), b.size(), q, f));

    // truncated buffer must not over-read or crash
    std::vector<uint8_t> good;
    bkv::subtreeBegin(good, "ufs");
    bkv::i32(good, "quota", 104857600u);
    bkv::i32(good, "maxnumfiles", 1000u);
    bkv::end(good);
    for (size_t cut = 0; cut < good.size(); ++cut) {
        uint64_t tq = 0; uint32_t tf = 0;
        // any prefix: returns true only if both fields fully present; never crashes
        CloudSaves::ParseUfsQuota(good.data(), cut, tq, tf);
    }
    CHECK(true);  // reached here without crashing
}

// Real UFS dumps for app 3756940 (The Ratline), captured live.
static const unsigned char kUfsInline[] = {
    0x00,'u','f','s',0x00,
    0x02,'q','u','o','t','a',0x00, 0xa0,0x86,0x01,0x00,
    0x02,'m','a','x','n','u','m','f','i','l','e','s',0x00, 0x64,0x00,0x00,0x00,
    0x02,'i','g','n','o','r','e','e','x','t','e','r','n','a','l','f','i','l','e','s',0x00, 0x01,0x00,0x00,0x00,
    0x02,'h','i','d','e','c','l','o','u','d','u','i',0x00, 0x01,0x00,0x00,0x00,
    0x08, 0x08
};
// ufs=0x00004f3b quota=0x0624 maxnumfiles=0x062a ignoreexternalfiles=0x75c1 hidecloudui=0x0618
static unsigned char kUfsPooled[] = {
    0x00, 0x3b,0x4f,0x00,0x00,
    0x02, 0x24,0x06,0x00,0x00, 0xa0,0x86,0x01,0x00,
    0x02, 0x2a,0x06,0x00,0x00, 0x64,0x00,0x00,0x00,
    0x02, 0xc1,0x75,0x00,0x00, 0x01,0x00,0x00,0x00,
    0x02, 0x18,0x06,0x00,0x00, 0x01,0x00,0x00,0x00,
    0x08, 0x08
};

static void test_reveal_resolve_index() {
    uint32_t idx = 0;
    bool ok = CloudSaves::ResolvePooledSymbolIndex(
        kUfsInline, sizeof(kUfsInline), kUfsPooled, sizeof(kUfsPooled),
        "hidecloudui", idx);
    assert(ok);
    assert(idx == 0x0618);
    uint32_t qidx = 0;
    assert(CloudSaves::ResolvePooledSymbolIndex(
        kUfsInline, sizeof(kUfsInline), kUfsPooled, sizeof(kUfsPooled),
        "quota", qidx));
    assert(qidx == 0x0624);
    uint32_t bad = 123;
    assert(!CloudSaves::ResolvePooledSymbolIndex(
        kUfsInline, sizeof(kUfsInline), kUfsPooled, sizeof(kUfsPooled),
        "doesnotexist", bad));
}

static void test_reveal_zero_pooled_int() {
    unsigned char buf[sizeof(kUfsPooled)];
    std::memcpy(buf, kUfsPooled, sizeof(kUfsPooled));
    bool changed = CloudSaves::ZeroPooledInt(buf, sizeof(buf), 0x0618);
    assert(changed);
    size_t voff = sizeof(buf) - 2 - 4;
    assert(buf[voff] == 0 && buf[voff+1] == 0 && buf[voff+2] == 0 && buf[voff+3] == 0);
    assert(sizeof(buf) == sizeof(kUfsPooled));
    unsigned char buf2[sizeof(kUfsPooled)];
    std::memcpy(buf2, kUfsPooled, sizeof(kUfsPooled));
    assert(!CloudSaves::ZeroPooledInt(buf2, sizeof(buf2), 0xDEADBEEF));
}

// Regression: GetMultipleAppDataSections returns a COMBINED common+extended+ufs
// buffer whose earlier sections contain int64 (0x0a) and alt-end (0x0b) nodes.
// The walkers must skip past these to reach a later hidecloudui int32. With the
// pre-fix type table they aborted at the first int64 and silently failed.
static void test_reveal_zero_past_int64_and_altend() {
    unsigned char buf[] = {
        0x00, 0x00,0x02,0x00,0x00,            // nested "common"-like subkey, idx 0x0200
          0x07, 0x01,0x01,0x00,0x00, 1,2,3,4,5,6,7,8,  // uint64 (already handled)
          0x0a, 0x02,0x01,0x00,0x00, 8,7,6,5,4,3,2,1,  // int64 (NEW: previously aborted)
          0x0b,                              // alt-end of the subkey (NEW)
        0x02, 0x18,0x06,0x00,0x00, 0x01,0x00,0x00,0x00, // hidecloudui int32 = 1, idx 0x0618
        0x08                                 // end
    };
    size_t voff = sizeof(buf) - 1 - 4;  // value of the trailing hidecloudui int32
    bool changed = CloudSaves::ZeroPooledInt(buf, sizeof(buf), 0x0618);
    assert(changed);
    assert(buf[voff] == 0 && buf[voff+1] == 0 && buf[voff+2] == 0 && buf[voff+3] == 0);
}

int main() {
    test_sha1_known_vectors();
    test_manifest_roundtrip();
    test_savestore_write_read_delete();
    test_savestore_manifest_persists();
    test_proctcp_parse();
    test_changelist_empty_is_delta();
    test_changelist_unresolved_account_is_delta();
    test_upload_commit_download_cycle();
    test_savestore_completeness_and_integrity();
    test_changelist_incomplete_is_delta();
    test_ufs_quota_typed_int();
    test_ufs_quota_string_values();
    test_ufs_quota_uint64_and_nested();
    test_ufs_quota_missing_field_fails();
    test_ufs_quota_implausible_fails();
    test_ufs_quota_zero_fails_and_truncation_safe();
    test_reveal_resolve_index();
    test_reveal_zero_pooled_int();
    test_reveal_zero_past_int64_and_altend();
    if (g_failures) { std::printf("%d check(s) failed\n", g_failures); return 1; }
    std::printf("all cloudsaves smoke checks passed\n");
    return 0;
}
