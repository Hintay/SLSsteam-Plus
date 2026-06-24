#include "log.hpp"

#include "syscalls.hpp"

#include <cstdlib>
#include <cstring>
#include <fcntl.h>

namespace sls::log {

namespace {

// Resolved once on first call. Sized to fit "$HOME/.sls_inject.log".
constexpr int kPathBufSize = 256;
constexpr int kSuffixReserve = 16;
char g_path[kPathBufSize];

void resolve_path_once() {
    if (g_path[0] != '\0') return;
    const char* home = std::getenv("HOME");
    if (!home) home = "/tmp";

    int i = 0;
    while (*home && i < kPathBufSize - kSuffixReserve) {
        g_path[i++] = *home++;
    }
    static constexpr char kSuffix[] = "/.sls_inject.log";
    for (int j = 0; kSuffix[j] && i < kPathBufSize - 1; j++) {
        g_path[i++] = kSuffix[j];
    }
    g_path[i] = '\0';
}

} // namespace

void dbg(const char* msg) {
    if (!msg) return;
    resolve_path_once();

    const int fd = sys::open(g_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    sys::write(fd, msg, std::strlen(msg));
    sys::write(fd, "\n", 1);
    sys::close(fd);
}

} // namespace sls::log
