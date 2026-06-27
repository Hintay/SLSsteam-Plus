#include "cloud_ui_reveal.hpp"
#include <cstring>

namespace CloudSaves {
namespace {

// Returns the fixed byte size of a leaf value type, -2 for NUL-terminated
// string, or -3 for unknown/unsupported type.
static int leafValueSize(uint8_t type) {
    switch (type) {
        case 0x01: return -2;       // string: NUL-terminated, variable length
        case 0x02: case 0x03: case 0x04: case 0x06: return 4;
        case 0x07: return 8;        // uint64
        case 0x0a: return 8;        // int64 (kInt64); matches appinfo_kv.cpp
        // 0x05 (wstring) intentionally unsupported -> sentinel; never present in practice
        default:   return -3;       // unknown/unsupported
    }
}

// Advance pos past the value of a leaf node in an inline (string-key) buffer.
static bool skipInlineValue(const uint8_t* b, size_t len, size_t& pos, uint8_t type) {
    int sz = leafValueSize(type);
    if (sz == -2) {
        // NUL-terminated string value
        while (pos < len && b[pos] != 0) ++pos;
        if (pos >= len) return false;
        ++pos;
        return true;
    }
    if (sz < 0) return false;
    if (pos + (size_t)sz > len) return false;
    pos += sz;
    return true;
}

}  // namespace

bool ResolvePooledSymbolIndex(const uint8_t* in, size_t inLen,
                              const uint8_t* pl, size_t plLen,
                              const char* keyName, uint32_t& outIndex) {
    size_t ip = 0, pp = 0;
    while (ip < inLen && pp < plLen) {
        uint8_t itype = in[ip++];
        uint8_t ptype = pl[pp++];
        // Both streams must agree on type; 0x08/0x0b are end markers (no key follows)
        if (itype != ptype) return false;
        if (itype == 0x08 || itype == 0x0b) continue;

        // Inline key: NUL-terminated string
        size_t nameStart = ip;
        while (ip < inLen && in[ip] != 0) ++ip;
        if (ip >= inLen) return false;
        size_t nameLen = ip - nameStart;
        ++ip;  // consume NUL

        // Pooled key: 4-byte little-endian symbol index
        if (pp + 4 > plLen) return false;
        uint32_t idx;
        std::memcpy(&idx, pl + pp, 4);
        pp += 4;

        bool match = (std::strlen(keyName) == nameLen) &&
                     (std::memcmp(in + nameStart, keyName, nameLen) == 0);

        if (itype == 0x00) {
            // Nested subkey: no value bytes follow; recurse into children next iteration
            if (match) { outIndex = idx; return true; }
            continue;
        }
        // Leaf node: check name match first
        if (match) { outIndex = idx; return true; }

        // Skip past the inline value
        if (!skipInlineValue(in, inLen, ip, itype)) return false;

        // Skip past the pooled value (same size, but strings use NUL in pooled too)
        if (itype == 0x01) {
            while (pp < plLen && pl[pp] != 0) ++pp;
            if (pp >= plLen) return false;
            ++pp;
        } else {
            int sz = leafValueSize(itype);
            if (sz < 0 || pp + (size_t)sz > plLen) return false;
            pp += sz;
        }
    }
    return false;
}

bool ZeroPooledInt(uint8_t* b, size_t len, uint32_t idx) {
    size_t pos = 0;
    while (pos < len) {
        uint8_t type = b[pos++];
        // 0x08 (end-of-subkey) and 0x0b (alt-end) are markers with no key/value
        if (type == 0x08 || type == 0x0b) continue;

        // Pooled key: 4-byte symbol index
        if (pos + 4 > len) return false;
        uint32_t key;
        std::memcpy(&key, b + pos, 4);
        pos += 4;

        if (type == 0x00) {
            // Nested subkey: no value bytes, children follow inline
            continue;
        }
        if (type == 0x02) {
            // int32 leaf
            if (pos + 4 > len) return false;
            if (key == idx) {
                int32_t v;
                std::memcpy(&v, b + pos, 4);
                if (v == 0) return false;  // already zero — no change
                int32_t z = 0;
                std::memcpy(b + pos, &z, 4);
                return true;
            }
            pos += 4;
            continue;
        }
        // Other leaf types: skip over value bytes
        if (type == 0x01) {
            // NUL-terminated string value
            while (pos < len && b[pos] != 0) ++pos;
            if (pos >= len) return false;
            ++pos;
            continue;
        }
        int sz = leafValueSize(type);
        if (sz < 0 || pos + (size_t)sz > len) return false;
        pos += sz;
    }
    return false;
}

}  // namespace CloudSaves
