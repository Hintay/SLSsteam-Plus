#pragma once
#include <cstddef>
#include <cstdint>

namespace CloudSaves {

// Parse a Steam binary-KeyValues blob (the standard WriteAsBinary form with
// inline NUL-terminated string keys, as produced by
// IClientApps::GetAppDataSection(..., bSharedKVSymbols=false)) and extract the
// UFS quota fields. Searches the whole tree for the "quota" and "maxnumfiles"
// keys (case-insensitive), regardless of nesting, accepting either a typed
// integer or a decimal-string value.
//
// Returns true only when both a plausible "quota" and "maxnumfiles" were found.
// On malformed input it stops early and returns false (fail-closed: the caller
// then falls back to its default quota). Never reads past data + len.
bool ParseUfsQuota(const uint8_t* data, size_t len,
                   uint64_t& outQuotaBytes, uint32_t& outMaxFiles);

}  // namespace CloudSaves
