#pragma once
#include "save_store.hpp"
#include <map>
#include <string>

namespace CloudSaves {

struct Manifest {
    uint64_t changeNumber = 0;
    std::map<std::string, FileEntry> files;   // keyed by relPath
};

// Minimal hand-rolled JSON (fixed shape). Deterministic key order (std::map).
std::string SerializeManifest(const Manifest& m);
bool ParseManifest(const std::string& text, Manifest& out);

}  // namespace CloudSaves
