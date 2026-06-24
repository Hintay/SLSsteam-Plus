#include "ipc.hpp"

#include "raii.hpp"
#include "syscalls.hpp"

#include "../../src/feats/protoninject_protocol.h"

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>

namespace sls::ipc {

namespace {

bool build_abstract_addr(const char* socket_name,
                        sockaddr_un& addr, socklen_t& addr_len) {
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    const size_t name_len = std::strlen(socket_name);
    if (name_len + 1 > sizeof(addr.sun_path)) return false;
    std::memcpy(addr.sun_path + 1, socket_name, name_len);
    addr_len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name_len);
    return true;
}

// Linux path → Wine NT path in UTF-16LE: "\??\unix" + path.
// Uses raw u16 (2-byte WCHAR), not the Linux 4-byte wchar_t.
void path_to_wine_nt(const char* path, uint16_t* out, size_t out_chars) {
    uint16_t* wp = out;
    const uint16_t* end = out + out_chars - 1;
    static constexpr char kPrefix[] = "\\??\\unix";
    for (int i = 0; kPrefix[i] && wp < end; i++) {
        *wp++ = static_cast<uint16_t>(static_cast<unsigned char>(kPrefix[i]));
    }
    for (const char* p = path; *p && wp < end; p++) {
        *wp++ = static_cast<uint16_t>(static_cast<unsigned char>(*p));
    }
    *wp = 0;
}

// Open the SLSsteam control socket, returning a connected fd or -1.
int connect_control_socket() {
    char socket_name[sizeof(sockaddr_un::sun_path) - 1] = {};
    if (!sls_proton_build_socket_name(socket_name, sizeof(socket_name),
                                       SLS_PROTON_INJECT_CONTROL_TOKEN)) {
        return -1;
    }
    sockaddr_un addr;
    socklen_t addr_len = 0;
    if (!build_abstract_addr(socket_name, addr, addr_len)) return -1;
    const int fd = sys::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (sys::connect(fd, reinterpret_cast<const sockaddr*>(&addr), addr_len) != 0) {
        sys::close(fd);
        return -1;
    }
    return fd;
}

} // namespace

bool resolve_dll_path(uint16_t* out, size_t out_chars) {
    if (!out || out_chars < 2) return false;
    out[0] = 0;

    const char* token = std::getenv(SLS_PROTON_INJECT_SESSION_ENV);
    if (!token || !token[0]) return false;

    ScopedFd fd(connect_control_socket());
    if (!fd.valid()) return false;

    sys::write(fd.get(), token, std::strlen(token));
    sys::write(fd.get(), "\n", 1);

    char response[1024] = {};
    const ssize_t n = sys::read(fd.get(), response, sizeof(response) - 1);
    if (n <= 0) return false;
    response[n] = '\0';

    uint32_t app_id = 0;
    char path_buf[512] = {};
    if (!sls_proton_parse_ok_response(response, &app_id, path_buf, sizeof(path_buf))) {
        return false;
    }
    (void)app_id;

    path_to_wine_nt(path_buf, out, out_chars);
    return true;
}

} // namespace sls::ipc
