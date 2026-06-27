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

    // Finalize a previously-staged file into files/ + update manifest. `timestamp`
    // is Steam's authoritative save time (0 => fall back to wall clock); it is
    // recorded in the manifest and applied as the file mtime so newest-wins stays
    // correct across machines. Returns false if no staged file matches.
    bool commit(uint32_t accountId, uint32_t appId, const std::string& relPath,
                uint64_t timestamp);

    // Read a committed file's bytes, verifying the content SHA-1 matches the
    // manifest. false if absent, unknown, or the on-disk bytes are corrupt /
    // only partially synced (SHA mismatch) — never serves bytes we can't vouch for.
    bool read(uint32_t accountId, uint32_t appId, const std::string& relPath,
              std::vector<uint8_t>& out);

    // Delete a committed file + manifest entry. Bumps change number. false if absent.
    bool remove(uint32_t accountId, uint32_t appId, const std::string& relPath);

    // List all committed files for an app (from the manifest = the expected set).
    std::vector<FileEntry> list(uint32_t accountId, uint32_t appId);

    // Fetch a single manifest entry (sha/size/timestamp) for a file. false if absent.
    bool entry(uint32_t accountId, uint32_t appId, const std::string& relPath,
               FileEntry& out);

    // True if every manifest-listed file is present on disk with matching size.
    // False => the store is mid-sync / incomplete, so callers must not present it
    // as the authoritative full set (else Steam would treat missing files as
    // deletions). Empty store counts as complete.
    bool isComplete(uint32_t accountId, uint32_t appId);

    // Coarse "is the store newer" gate, derived from content: the max file
    // timestamp across the manifest (0 if empty). Content-derived rather than a
    // counter so two machines holding the same files compute the same value — no
    // multi-master counter collisions under Syncthing/rclone.
    uint64_t changeNumber(uint32_t accountId, uint32_t appId);

    // Clear stale staging files left by interrupted uploads. Call at startup.
    void sweepStaging();

private:
    std::string m_root;
};

}  // namespace CloudSaves
