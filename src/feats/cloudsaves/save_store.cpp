#include "save_store.hpp"
#include "manifest.hpp"
#include "sha1.hpp"

#include <atomic>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <unordered_map>

namespace fs = std::filesystem;

namespace CloudSaves {

namespace {
std::mutex g_lock;   // coarse lock; per-(account,app) granularity is fine in practice

std::string appDir(const std::string& root, uint32_t acc, uint32_t app) {
    return root + "/" + std::to_string(acc) + "/" + std::to_string(app);
}
std::string filesDir(const std::string& d)   { return d + "/files"; }
std::string stagingDir(const std::string& d) { return d + "/staging"; }
std::string manifestPath(const std::string& d) { return d + "/manifest.json"; }

Manifest loadManifest(const std::string& dir) {
    Manifest m;
    std::ifstream f(manifestPath(dir), std::ios::binary);
    if (!f) return m;
    std::string text((std::istreambuf_iterator<char>(f)), {});
    ParseManifest(text, m);
    return m;
}

bool saveManifest(const std::string& dir, const Manifest& m) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    std::string tmp = manifestPath(dir) + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f << SerializeManifest(m);
        if (!f) return false;
    }
    fs::rename(tmp, manifestPath(dir), ec);
    return !ec;
}

bool readFileBytes(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out.assign((std::istreambuf_iterator<char>(f)), {});
    return true;
}

// Encode a relPath into a single staging filename (slashes -> '%2f').
std::string stagingName(const std::string& relPath) {
    std::string s;
    for (char c : relPath) { if (c == '/') s += "%2f"; else s += c; }
    return s;
}
}  // namespace

SaveStore::SaveStore(std::string rootDir) : m_root(std::move(rootDir)) {}

std::string SaveStore::beginStaging(uint32_t acc, uint32_t app, const std::string& relPath) {
    std::lock_guard<std::mutex> lk(g_lock);
    std::string d = appDir(m_root, acc, app);
    std::error_code ec;
    fs::create_directories(stagingDir(d), ec);
    if (ec) return {};
    return stagingDir(d) + "/" + stagingName(relPath);
}

bool SaveStore::commit(uint32_t acc, uint32_t app, const std::string& relPath) {
    std::lock_guard<std::mutex> lk(g_lock);
    std::string d = appDir(m_root, acc, app);
    std::string staged = stagingDir(d) + "/" + stagingName(relPath);
    std::error_code ec;
    if (!fs::exists(staged, ec)) return false;

    std::vector<uint8_t> bytes;
    if (!readFileBytes(staged, bytes)) return false;

    std::string dst = filesDir(d) + "/" + relPath;
    fs::create_directories(fs::path(dst).parent_path(), ec);
    fs::rename(staged, dst, ec);
    if (ec) {
        // cross-dir rename fallback: copy then remove
        std::ofstream o(dst, std::ios::binary | std::ios::trunc);
        if (!o) return false;
        o.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        if (!o) return false;
        fs::remove(staged, ec);
    }

    Manifest m = loadManifest(d);
    FileEntry fe;
    fe.relPath = relPath;
    fe.shaHex = Sha1Hex(bytes.data(), bytes.size());
    fe.size = bytes.size();
    fe.timestamp = static_cast<uint64_t>(::time(nullptr));
    m.files[relPath] = fe;
    m.changeNumber += 1;
    return saveManifest(d, m);
}

bool SaveStore::read(uint32_t acc, uint32_t app, const std::string& relPath,
                     std::vector<uint8_t>& out) {
    std::lock_guard<std::mutex> lk(g_lock);
    std::string dst = filesDir(appDir(m_root, acc, app)) + "/" + relPath;
    return readFileBytes(dst, out);
}

bool SaveStore::remove(uint32_t acc, uint32_t app, const std::string& relPath) {
    std::lock_guard<std::mutex> lk(g_lock);
    std::string d = appDir(m_root, acc, app);
    std::string dst = filesDir(d) + "/" + relPath;
    std::error_code ec;
    bool existed = fs::remove(dst, ec);
    Manifest m = loadManifest(d);
    auto it = m.files.find(relPath);
    if (it == m.files.end() && !existed) return false;
    if (it != m.files.end()) m.files.erase(it);
    m.changeNumber += 1;
    return saveManifest(d, m);
}

std::vector<FileEntry> SaveStore::list(uint32_t acc, uint32_t app) {
    std::lock_guard<std::mutex> lk(g_lock);
    Manifest m = loadManifest(appDir(m_root, acc, app));
    std::vector<FileEntry> out;
    out.reserve(m.files.size());
    for (auto& [k, v] : m.files) out.push_back(v);
    return out;
}

uint64_t SaveStore::changeNumber(uint32_t acc, uint32_t app) {
    std::lock_guard<std::mutex> lk(g_lock);
    return loadManifest(appDir(m_root, acc, app)).changeNumber;
}

void SaveStore::sweepStaging() {
    std::lock_guard<std::mutex> lk(g_lock);
    std::error_code ec;
    for (auto& acc : fs::directory_iterator(m_root, ec)) {
        if (ec) break;
        for (auto& app : fs::directory_iterator(acc.path(), ec)) {
            std::string s = app.path().string() + "/staging";
            fs::remove_all(s, ec);
        }
    }
}

}  // namespace CloudSaves
