#include "cloud_enable_policy.hpp"
#include <cstdlib>
#include <cstring>
#include <string>

namespace CloudSaves {

bool DecideCloudEnabled(bool origEnabled, bool userDisabled, bool accountMasterOn) {
    if (origEnabled)      return true;   // already on — nothing to change
    if (userDisabled)     return false;  // user explicitly turned off — respect it
    if (!accountMasterOn) return false;  // account-level master is off — respect it
    return true;                         // force on: neutralize the hidecloudui enable-gate
}

void ParseDisabledCloudApps(const char* text, size_t len,
                            std::unordered_set<uint32_t>& out) {
    std::string text_s(text, len);
    size_t i = 0;
    uint32_t curApp = 0;

    // Read a quoted token starting at text_s[pos] (which must be '"').
    // Returns the position after the closing '"'.
    auto readQuoted = [&](size_t pos, std::string& tok) -> size_t {
        size_t s = pos + 1, e = s;
        while (e < text_s.size() && text_s[e] != '"') ++e;
        tok.assign(text_s, s, e - s);
        return (e < text_s.size()) ? e + 1 : e;
    };

    while (i < text_s.size()) {
        char c = text_s[i];
        if (c == '"') {
            std::string key;
            size_t after = readQuoted(i, key);

            // Skip whitespace to see whether the next token is a quoted value
            // (key-value pair) or a '{' / another key (standalone key = appid block header).
            size_t j = after;
            while (j < text_s.size() &&
                   (text_s[j] == ' ' || text_s[j] == '\t' ||
                    text_s[j] == '\r' || text_s[j] == '\n')) {
                ++j;
            }

            if (j < text_s.size() && text_s[j] == '"') {
                // key "value" pair
                std::string val;
                size_t after2 = readQuoted(j, val);
                if (key == "cloudenabled" && val == "0" && curApp != 0)
                    out.insert(curApp);
                i = after2;
                continue;
            }

            // Standalone quoted key — if all digits, treat as the current appid block.
            bool allDigits = !key.empty();
            for (char d : key) {
                if (d < '0' || d > '9') { allDigits = false; break; }
            }
            if (allDigits)
                curApp = static_cast<uint32_t>(std::strtoul(key.c_str(), nullptr, 10));

            i = after;
            continue;
        }
        ++i;
    }
}

}  // namespace CloudSaves
