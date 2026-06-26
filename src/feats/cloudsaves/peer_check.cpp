#include "peer_check.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_set>

namespace CloudSaves {

bool ParseProcTcpLine(const std::string& line, uint16_t& localPort, uint64_t& inode) {
    std::istringstream is(line);
    std::string sl, local, rem, st, txrx, trtm, retr, uid, timeout, inodeStr;
    if (!(is >> sl >> local >> rem >> st >> txrx >> trtm >> retr >> uid >> timeout >> inodeStr))
        return false;
    if (sl == "sl") return false;  // header
    size_t colon = local.find(':');
    if (colon == std::string::npos) return false;
    localPort = static_cast<uint16_t>(std::strtoul(local.c_str() + colon + 1, nullptr, 16));
    inode = std::strtoull(inodeStr.c_str(), nullptr, 10);
    return true;
}

namespace {
uint64_t inodeForLocalPort(const char* path, uint16_t port) {
    std::ifstream f(path);
    if (!f) return 0;
    std::string line;
    std::getline(f, line);  // header
    while (std::getline(f, line)) {
        uint16_t p = 0; uint64_t ino = 0;
        if (ParseProcTcpLine(line, p, ino) && p == port) return ino;
    }
    return 0;
}

bool ownProcHoldsInode(uint64_t inode) {
    std::string want = "socket:[" + std::to_string(inode) + "]";
    DIR* d = opendir("/proc/self/fd");
    if (!d) return false;
    bool found = false;
    struct dirent* e;
    char buf[256];
    while ((e = readdir(d)) != nullptr) {
        std::string link = std::string("/proc/self/fd/") + e->d_name;
        ssize_t n = readlink(link.c_str(), buf, sizeof(buf) - 1);
        if (n <= 0) continue;
        buf[n] = '\0';
        if (want == buf) { found = true; break; }
    }
    closedir(d);
    return found;
}
}  // namespace

bool PeerIsOwnProcess(uint16_t peerPort) {
    uint64_t inode = inodeForLocalPort("/proc/net/tcp", peerPort);
    if (!inode) inode = inodeForLocalPort("/proc/net/tcp6", peerPort);
    if (!inode) return false;
    return ownProcHoldsInode(inode);
}

}  // namespace CloudSaves
