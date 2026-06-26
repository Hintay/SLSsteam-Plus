// Standalone smoke tests for the Cloud Saves pure units (SaveStore, RpcEngine).
// No Steam, no protobuf-linked SLSsteam types beyond the generated cloud messages.
// Build: make bin/cloudsaves_smoke && ./bin/cloudsaves_smoke
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <filesystem>
#include <vector>

#include "feats/cloudsaves/sha1.hpp"
#include "feats/cloudsaves/manifest.hpp"
#include "feats/cloudsaves/save_store.hpp"
#include "feats/cloudsaves/peer_check.hpp"
#include "slssteam_messages.pb.h"
#include "feats/cloudsaves/rpc_engine.hpp"

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
    CHECK(store.commit(123, 480, "save/slot0.dat"));

    // change number bumped to 1
    CHECK(store.changeNumber(123, 480) == 1);

    // read back
    std::vector<uint8_t> out;
    CHECK(store.read(123, 480, "save/slot0.dat", out));
    CHECK(out.size() == 5);
    CHECK(std::string(out.begin(), out.end()) == "hello");

    // list reflects it with sha of "hello"
    auto files = store.list(123, 480);
    CHECK(files.size() == 1);
    CHECK(files[0].relPath == "save/slot0.dat");
    CHECK(files[0].size == 5);
    CHECK(files[0].shaHex == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"); // sha1("hello")

    // delete bumps change number, removes file
    CHECK(store.remove(123, 480, "save/slot0.dat"));
    CHECK(store.changeNumber(123, 480) == 2);
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
        store.commit(1, 2, "a.dat");
    }
    // New instance reads persisted manifest
    CloudSaves::SaveStore store2(root);
    CHECK(store2.changeNumber(1, 2) == 1);
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
    CHECK(store.changeNumber(777, 480) == 1);

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

    // Delete
    CCloud_ClientDeleteFile_Request del; del.set_appid(480); del.set_filename("save/a.dat");
    CHECK(eng.handle("Cloud.ClientDeleteFile#1", 480, 777, del.SerializeAsString(), respBytes, e));
    CHECK(store.changeNumber(777, 480) == 2);
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
    if (g_failures) { std::printf("%d check(s) failed\n", g_failures); return 1; }
    std::printf("all cloudsaves smoke checks passed\n");
    return 0;
}
