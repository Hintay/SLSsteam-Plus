#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace CloudSaves {

struct FileEntry {
    std::string relPath;      // forward-slash relative path, e.g. "save/slot0.dat"
    std::string shaHex;       // 40-char lowercase SHA-1 hex
    uint64_t    size = 0;
    uint64_t    timestamp = 0;
};

// Local-folder save store for one storage root. Thread-safe per (accountId, appId).
class SaveStore {
public:
    explicit SaveStore(std::string rootDir);   // e.g. ~/.local/share/SLSsteam/cloudsaves

    // Returns the staging path to write upload bytes into; caller (HTTP PUT) writes
    // bytes there. relPath identifies the eventual file. Empty string on error.
    std::string beginStaging(uint32_t accountId, uint32_t appId, const std::string& relPath);

    // Finalize a previously-staged file into files/ + update manifest. Bumps change
    // number. Returns false if no staged file matches.
    bool commit(uint32_t accountId, uint32_t appId, const std::string& relPath);

    // Read a committed file's bytes. false if absent.
    bool read(uint32_t accountId, uint32_t appId, const std::string& relPath,
              std::vector<uint8_t>& out);

    // Delete a committed file + manifest entry. Bumps change number. false if absent.
    bool remove(uint32_t accountId, uint32_t appId, const std::string& relPath);

    // List all committed files for an app.
    std::vector<FileEntry> list(uint32_t accountId, uint32_t appId);

    uint64_t changeNumber(uint32_t accountId, uint32_t appId);

    // Clear stale staging files left by interrupted uploads. Call at startup.
    void sweepStaging();

private:
    std::string m_root;
};

}  // namespace CloudSaves
