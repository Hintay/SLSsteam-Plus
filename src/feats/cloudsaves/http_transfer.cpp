#include "http_transfer.hpp"
#include "peer_check.hpp"
#include "../../log.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace CloudSaves {

namespace {
constexpr int64_t kMaxUploadBytes = 256LL * 1024 * 1024;  // 256 MiB cap

std::string urlDecode(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            int hi = std::strtol(s.substr(i+1,1).c_str(), nullptr, 16);
            int lo = std::strtol(s.substr(i+2,1).c_str(), nullptr, 16);
            out += static_cast<char>((hi << 4) | lo);
            i += 2;
        } else if (s[i] == '+') out += ' ';
        else out += s[i];
    }
    return out;
}

// Path: /<acc>/<app>/<urlencoded-relpath>. relpath may contain encoded slashes.
bool parsePath(const std::string& path, uint32_t& acc, uint32_t& app, std::string& rel) {
    if (path.empty() || path[0] != '/') return false;
    size_t a = path.find('/', 1);
    if (a == std::string::npos) return false;
    size_t b = path.find('/', a + 1);
    if (b == std::string::npos) return false;
    acc = std::strtoul(path.substr(1, a - 1).c_str(), nullptr, 10);
    app = std::strtoul(path.substr(a + 1, b - a - 1).c_str(), nullptr, 10);
    rel = urlDecode(path.substr(b + 1));
    if (rel.empty() || rel.find("..") != std::string::npos) return false;  // traversal guard
    return true;
}

void sendStatus(int fd, const char* status, const std::string& body = {}) {
    std::string resp = std::string("HTTP/1.1 ") + status + "\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    ::send(fd, resp.data(), resp.size(), 0);
}

// Peer verification with a short retry for the /proc inode-population race.
bool verifyPeer(int clientFd) {
    sockaddr_in peer{};
    socklen_t plen = sizeof(peer);
    if (::getpeername(clientFd, reinterpret_cast<sockaddr*>(&peer), &plen) != 0) return false;
    uint16_t peerPort = ntohs(peer.sin_port);
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (CloudSaves::PeerIsOwnProcess(peerPort)) return true;
        usleep(2000);  // 2ms; inode may not be in /proc yet at connect time
    }
    return false;
}

void handleClient(int fd, SaveStore& store) {
    // Read headers (up to \r\n\r\n), cap 16KB.
    std::string head;
    char buf[4096];
    int headerEnd = -1;
    while (head.size() < 16384) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        head.append(buf, static_cast<size_t>(n));
        size_t pos = head.find("\r\n\r\n");
        if (pos != std::string::npos) { headerEnd = static_cast<int>(pos) + 4; break; }
    }
    if (headerEnd < 0) { sendStatus(fd, "400 Bad Request"); return; }

    char method[8] = {}, path[2048] = {};
    if (std::sscanf(head.c_str(), "%7s %2047s", method, path) != 2) {
        sendStatus(fd, "400 Bad Request"); return;
    }

    uint32_t acc = 0, app = 0; std::string rel;
    if (!parsePath(path, acc, app, rel)) { sendStatus(fd, "400 Bad Request"); return; }

    if (std::strcmp(method, "PUT") == 0) {
        // Content-Length
        int64_t clen = 0;
        size_t clp = head.find("Content-Length:");
        if (clp == std::string::npos) clp = head.find("content-length:");
        if (clp != std::string::npos) clen = std::strtoll(head.c_str() + clp + 15, nullptr, 10);
        if (clen < 0 || clen > kMaxUploadBytes) { sendStatus(fd, "413 Payload Too Large"); return; }

        std::string staging = store.beginStaging(acc, app, rel);
        if (staging.empty()) { sendStatus(fd, "500 Internal Server Error"); return; }
        FILE* out = std::fopen(staging.c_str(), "wb");
        if (!out) { sendStatus(fd, "500 Internal Server Error"); return; }

        // write body bytes already read past the header
        int64_t written = 0;
        size_t pre = head.size() - static_cast<size_t>(headerEnd);
        if (pre > 0) { std::fwrite(head.data() + headerEnd, 1, pre, out); written += pre; }
        while (written < clen) {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            std::fwrite(buf, 1, static_cast<size_t>(n), out);
            written += n;
        }
        std::fclose(out);
        if (written != clen) { sendStatus(fd, "400 Bad Request"); return; }
        sendStatus(fd, "200 OK");
        return;
    }

    if (std::strcmp(method, "GET") == 0) {
        std::vector<uint8_t> bytes;
        if (!store.read(acc, app, rel, bytes)) { sendStatus(fd, "404 Not Found"); return; }
        std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: " +
            std::to_string(bytes.size()) + "\r\nConnection: close\r\n\r\n";
        ::send(fd, resp.data(), resp.size(), 0);
        ::send(fd, bytes.data(), bytes.size(), 0);
        return;
    }

    sendStatus(fd, "405 Method Not Allowed");
}

// Forward-declared before start() so pthread_create can take its address.
void* acceptLoopThunk(void* selfV);
}  // namespace

HttpTransfer::HttpTransfer(SaveStore& store) : m_store(store) {}
HttpTransfer::~HttpTransfer() { stop(); }

bool HttpTransfer::start() {
    m_listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (m_listenFd < 0) return false;
    int one = 1;
    ::setsockopt(m_listenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;  // OS-assigned
    if (::bind(m_listenFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(m_listenFd); m_listenFd = -1; return false;
    }
    socklen_t alen = sizeof(addr);
    if (::getsockname(m_listenFd, reinterpret_cast<sockaddr*>(&addr), &alen) < 0) {
        ::close(m_listenFd); m_listenFd = -1; return false;
    }
    m_port = ntohs(addr.sin_port);
    if (::listen(m_listenFd, 16) < 0) { ::close(m_listenFd); m_listenFd = -1; return false; }

    m_running = true;
    auto* tid = new pthread_t;
    if (pthread_create(tid, nullptr, &acceptLoopThunk, this) != 0) {
        delete tid; m_running = false; ::close(m_listenFd); m_listenFd = -1; return false;
    }
    m_threadHandle = tid;
    g_pLog->info("CloudSaves: HTTP transfer on 127.0.0.1:%u\n", m_port);
    return true;
}

void HttpTransfer::stop() {
    if (!m_running) return;
    m_running = false;
    if (m_listenFd >= 0) { ::shutdown(m_listenFd, SHUT_RDWR); ::close(m_listenFd); m_listenFd = -1; }
    if (m_threadHandle) {
        auto* tid = static_cast<pthread_t*>(m_threadHandle);
        pthread_join(*tid, nullptr);
        delete tid;
        m_threadHandle = nullptr;
    }
}

void HttpTransfer::acceptLoop() {
    while (m_running) {
        int client = ::accept(m_listenFd, nullptr, nullptr);
        if (client < 0) { if (m_running) continue; else break; }
        // Guard the single transfer thread: a half-open or stalled connection must not
        // block recv/send forever. 15s recv + send timeout on the accepted socket.
        struct timeval tv; tv.tv_sec = 15; tv.tv_usec = 0;
        ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (!verifyPeer(client)) { ::close(client); continue; }
        handleClient(client, m_store);
        ::close(client);
    }
}

namespace {
void* acceptLoopThunk(void* selfV) {
    auto* self = static_cast<HttpTransfer*>(selfV);
    self->acceptLoop();
    return nullptr;
}
}  // namespace

}  // namespace CloudSaves
