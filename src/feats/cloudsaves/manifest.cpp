#include "manifest.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace CloudSaves {

static void appendEscaped(std::string& s, const std::string& v) {
    s += '"';
    for (char c : v) {
        if (c == '"' || c == '\\') { s += '\\'; s += c; }
        else if (c == '\n') { s += "\\n"; }
        else s += c;
    }
    s += '"';
}

std::string SerializeManifest(const Manifest& m) {
    std::string s = "{\n";
    s += "  \"change_number\": " + std::to_string(m.changeNumber) + ",\n";
    s += "  \"files\": {\n";
    bool first = true;
    for (const auto& [name, fe] : m.files) {
        if (!first) s += ",\n";
        first = false;
        s += "    ";
        appendEscaped(s, name);
        s += ": { \"sha\": ";
        appendEscaped(s, fe.shaHex);
        s += ", \"size\": " + std::to_string(fe.size);
        s += ", \"timestamp\": " + std::to_string(fe.timestamp);
        s += " }";
    }
    s += "\n  }\n}\n";
    return s;
}

// Tolerant minimal parser: scans for the known keys. Not a general JSON parser,
// but matches exactly what SerializeManifest emits.
namespace {
bool readString(const char*& p, const char* end, std::string& out) {
    while (p < end && *p != '"') ++p;
    if (p >= end) return false;
    ++p;
    out.clear();
    while (p < end && *p != '"') {
        if (*p == '\\' && p + 1 < end) { ++p; out += (*p == 'n') ? '\n' : *p; }
        else out += *p;
        ++p;
    }
    if (p >= end) return false;
    ++p;
    return true;
}
uint64_t readNumberAfter(const std::string& hay, size_t pos) {
    size_t i = hay.find(':', pos);
    if (i == std::string::npos) return 0;
    return std::strtoull(hay.c_str() + i + 1, nullptr, 10);
}
}

bool ParseManifest(const std::string& text, Manifest& out) {
    out = Manifest{};
    size_t cn = text.find("\"change_number\"");
    if (cn == std::string::npos) return false;
    out.changeNumber = readNumberAfter(text, cn);

    size_t filesPos = text.find("\"files\"");
    if (filesPos == std::string::npos) return false;
    size_t brace = text.find('{', filesPos);
    if (brace == std::string::npos) return false;

    const char* p = text.c_str() + brace + 1;
    const char* end = text.c_str() + text.size();
    // Each entry: "<name>": { "sha": "<sha>", "size": N, "timestamp": N }
    while (true) {
        std::string name;
        const char* save = p;
        if (!readString(p, end, name)) { p = save; break; }
        // Heuristic: a file entry's name is followed by ": {"; the closing "}" of
        // files has no further quoted key. If next non-space isn't ':', we're done.
        const char* q = p;
        while (q < end && (*q == ' ' || *q == '\n' || *q == '\t')) ++q;
        if (q >= end || *q != ':') break;
        std::string sha;
        if (!readString(p, end, /*the "sha" key*/ sha)) break;  // consumes "sha"
        std::string shaVal;
        if (!readString(p, end, shaVal)) break;                  // consumes value
        size_t off = static_cast<size_t>(p - text.c_str());
        FileEntry fe;
        fe.relPath = name;
        fe.shaHex = shaVal;
        size_t sizePos = text.find("\"size\"", off);
        size_t tsPos = text.find("\"timestamp\"", off);
        if (sizePos == std::string::npos || tsPos == std::string::npos) break;
        fe.size = readNumberAfter(text, sizePos);
        fe.timestamp = readNumberAfter(text, tsPos);
        out.files[name] = fe;
        p = text.c_str() + tsPos;
        // advance past this entry's closing brace
        const char* cb = strchr(p, '}');
        if (!cb) break;
        p = cb + 1;
    }
    return true;
}

}  // namespace CloudSaves
