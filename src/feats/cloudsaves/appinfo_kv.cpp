#include "appinfo_kv.hpp"

#include <cctype>
#include <cstring>
#include <string>

namespace CloudSaves {
namespace {

// Plausibility bounds; reject pointer-sized garbage or a mis-parsed blob.
constexpr uint64_t kMaxPlausibleQuotaBytes = 1024ULL * 1024 * 1024 * 1024;  // 1 TiB
constexpr uint64_t kMaxPlausibleMaxFiles   = 10ULL * 1000 * 1000;           // 10M

// Standard Valve binary-KeyValues type markers (KeyValues::WriteAsBinary).
enum KvType : uint8_t {
    kNone    = 0,   // subtree: children follow until kEnd
    kString  = 1,   // NUL-terminated UTF-8
    kInt32   = 2,   // 4 bytes LE
    kFloat32 = 3,   // 4 bytes
    kPtr     = 4,   // 4 bytes
    kWString = 5,   // unsupported (never present in the ufs section)
    kColor   = 6,   // 4 bytes
    kUInt64  = 7,   // 8 bytes LE
    kEnd     = 8,   // end of the current subtree
    kInt64   = 10,  // 8 bytes LE
    kAltEnd  = 11,  // alternate end marker
};

struct Cursor {
    const uint8_t* p;
    const uint8_t* end;
    bool ok = true;
};

uint8_t readByte(Cursor& c) {
    if (c.p >= c.end) { c.ok = false; return 0; }
    return *c.p++;
}

// Reads a NUL-terminated string and advances past the terminator.
bool readCStr(Cursor& c, std::string& out) {
    out.clear();
    while (c.p < c.end) {
        uint8_t b = *c.p++;
        if (b == 0) return true;
        out.push_back(static_cast<char>(b));
    }
    c.ok = false;  // ran off the end with no terminator
    return false;
}

uint32_t readU32(Cursor& c) {
    if (c.p + 4 > c.end) { c.ok = false; return 0; }
    uint32_t v;
    std::memcpy(&v, c.p, 4);  // target is little-endian (i686 / x86_64)
    c.p += 4;
    return v;
}

uint64_t readU64(Cursor& c) {
    if (c.p + 8 > c.end) { c.ok = false; return 0; }
    uint64_t v;
    std::memcpy(&v, c.p, 8);
    c.p += 8;
    return v;
}

bool iequals(const std::string& a, const char* b) {
    size_t i = 0;
    for (; i < a.size(); ++i) {
        if (!b[i]) return false;
        if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i]))
            return false;
    }
    return b[i] == 0;
}

bool parseDecimal(const std::string& s, uint64_t& out) {
    if (s.empty()) return false;
    uint64_t v = 0;
    for (char ch : s) {
        if (ch < '0' || ch > '9') return false;
        v = v * 10 + uint64_t(ch - '0');
    }
    out = v;
    return true;
}

struct Found {
    bool     haveQuota = false;
    bool     haveFiles = false;
    uint64_t quota = 0;
    uint64_t files = 0;
};

void recordIfTarget(const std::string& key, bool isString,
                    const std::string& sval, uint64_t ival, Found& f) {
    uint64_t v = 0;
    if (isString) { if (!parseDecimal(sval, v)) return; }
    else          { v = ival; }
    if (iequals(key, "quota"))            { f.quota = v; f.haveQuota = true; }
    else if (iequals(key, "maxnumfiles")) { f.files = v; f.haveFiles = true; }
}

// Recursive descent over one subtree level. Depth-limited so malformed nesting
// can't blow the stack.
void parseLevel(Cursor& c, Found& f, int depth) {
    if (depth > 32) { c.ok = false; return; }
    while (c.ok && c.p < c.end) {
        uint8_t type = readByte(c);
        if (!c.ok) return;
        if (type == kEnd || type == kAltEnd) return;

        std::string key;
        if (!readCStr(c, key)) return;

        switch (type) {
            case kNone:
                parseLevel(c, f, depth + 1);
                break;
            case kString: {
                std::string val;
                if (!readCStr(c, val)) return;
                recordIfTarget(key, /*isString=*/true, val, 0, f);
                break;
            }
            case kInt32:
            case kPtr:
            case kColor: {
                uint32_t v = readU32(c);
                recordIfTarget(key, false, std::string(), v, f);
                break;
            }
            case kFloat32:
                (void)readU32(c);
                break;
            case kUInt64:
            case kInt64: {
                uint64_t v = readU64(c);
                recordIfTarget(key, false, std::string(), v, f);
                break;
            }
            case kWString:
            default:
                // Unknown/unsupported type: length is unknowable, so we can't
                // safely skip it. Stop here (anything found so far is kept).
                c.ok = false;
                return;
        }
    }
}

}  // namespace

bool ParseUfsQuota(const uint8_t* data, size_t len,
                   uint64_t& outQuotaBytes, uint32_t& outMaxFiles) {
    outQuotaBytes = 0;
    outMaxFiles = 0;
    if (!data || len == 0) return false;

    Cursor c{data, data + len, true};
    Found f;
    parseLevel(c, f, 0);

    if (!f.haveQuota || !f.haveFiles) return false;
    if (f.quota == 0 || f.files == 0) return false;
    if (f.quota > kMaxPlausibleQuotaBytes) return false;
    if (f.files > kMaxPlausibleMaxFiles)   return false;

    outQuotaBytes = f.quota;
    outMaxFiles   = static_cast<uint32_t>(f.files);
    return true;
}

}  // namespace CloudSaves
