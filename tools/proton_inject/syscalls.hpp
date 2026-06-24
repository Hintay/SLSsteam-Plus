// Raw syscall wrappers — safe to call from a clone() thread that lacks a TCB.
// glibc's libc wrappers touch errno and other TLS state that the clone thread
// doesn't have; these direct syscalls bypass all of that.
#pragma once

#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

namespace sls::sys {

inline int open(const char* path, int flags, int mode = 0) {
    return static_cast<int>(::syscall(SYS_openat, AT_FDCWD, path, flags, mode));
}
inline ssize_t read(int fd, void* buf, size_t count) {
    return static_cast<ssize_t>(::syscall(SYS_read, fd, buf, count));
}
inline ssize_t write(int fd, const void* buf, size_t count) {
    return static_cast<ssize_t>(::syscall(SYS_write, fd, buf, count));
}
inline int close(int fd) {
    return static_cast<int>(::syscall(SYS_close, fd));
}
inline off_t lseek(int fd, off_t offset, int whence) {
    return static_cast<off_t>(::syscall(SYS_lseek, fd, offset, whence));
}
inline int socket(int domain, int type, int protocol) {
    return static_cast<int>(::syscall(SYS_socket, domain, type, protocol));
}
inline int connect(int fd, const sockaddr* addr, socklen_t len) {
    return static_cast<int>(::syscall(SYS_connect, fd, addr, len));
}
inline void* mmap(void* addr, size_t len, int prot, int flags, int fd, off_t off) {
    return reinterpret_cast<void*>(::syscall(SYS_mmap, addr, len, prot, flags, fd, off));
}
inline int munmap(void* addr, size_t len) {
    return static_cast<int>(::syscall(SYS_munmap, addr, len));
}
inline int mprotect(void* addr, size_t len, int prot) {
    return static_cast<int>(::syscall(SYS_mprotect, addr, len, prot));
}
inline void sleep_ms(unsigned ms) {
    timespec ts{ms / 1000, static_cast<long>((ms % 1000) * 1000000L)};
    ::syscall(SYS_nanosleep, &ts, nullptr);
}

inline constexpr size_t kFallbackPageSize = 4096;

inline size_t page_size() {
    const long ps = ::sysconf(_SC_PAGESIZE);
    return ps > 0 ? static_cast<size_t>(ps) : kFallbackPageSize;
}

inline uintptr_t page_align_down(uintptr_t addr, size_t ps) {
    return addr & ~(static_cast<uintptr_t>(ps) - 1);
}

inline size_t page_span_len(uintptr_t addr, size_t len, size_t ps) {
    const uintptr_t start = page_align_down(addr, ps);
    const uintptr_t end = page_align_down(addr + len - 1, ps) + ps;
    return static_cast<size_t>(end - start);
}

} // namespace sls::sys
