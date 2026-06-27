#pragma once
#include <cstddef>
#include <cstdint>

namespace CloudSaves {

// Walk an inline (bShared=0, NUL-terminated string keys) and a pooled
// (bShared=1, 4-byte symbol-index keys) serialization of the SAME KeyValues
// section in lockstep. Both encode the same tree in the same order, so the
// pooled symbol index of the key whose inline name == keyName can be recovered.
// Returns true and sets outIndex on the first match; false if not found or on
// malformed input. Never reads past either buffer end.
bool ResolvePooledSymbolIndex(const uint8_t* inlineBuf, size_t inlineLen,
                              const uint8_t* pooledBuf, size_t pooledLen,
                              const char* keyName, uint32_t& outIndex);

// In a pooled binary-KV buffer, find an int32 node whose key symbol index
// equals idx and set its value to 0. Returns true if such a node was found and
// its value changed (already-zero counts as found, returns false for "changed").
// Walks structurally (does not pattern-match raw bytes) to avoid false hits
// inside values. Never reads/writes past buf+len.
bool ZeroPooledInt(uint8_t* buf, size_t len, uint32_t idx);

}  // namespace CloudSaves
