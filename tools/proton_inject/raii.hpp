// RAII wrappers for fd and mmap regions. Header-only, zero runtime deps.
// Used to make error paths in maps/elf/pe parsers leak-free.
#pragma once

#include "syscalls.hpp"

#include <cstddef>
#include <sys/mman.h>

namespace sls {

class ScopedFd {
public:
    ScopedFd() = default;
    explicit ScopedFd(int fd) : fd_(fd) {}
    ~ScopedFd() { reset(); }

    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;
    ScopedFd(ScopedFd&& other) noexcept : fd_(other.release()) {}
    ScopedFd& operator=(ScopedFd&& other) noexcept {
        reset(other.release());
        return *this;
    }

    int get() const { return fd_; }
    bool valid() const { return fd_ >= 0; }
    int release() {
        const int f = fd_;
        fd_ = -1;
        return f;
    }
    void reset(int fd = -1) {
        if (fd_ >= 0) sys::close(fd_);
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

// RAII anonymous mmap. We use mmap rather than malloc to stay safe in
// clone() threads without a TCB.
class ScopedMmap {
public:
    ScopedMmap() = default;
    ScopedMmap(size_t len, int prot, int flags)
        : ptr_(sys::mmap(nullptr, len, prot, flags, -1, 0)), len_(len) {
        if (ptr_ == MAP_FAILED) {
            ptr_ = nullptr;
            len_ = 0;
        }
    }
    ~ScopedMmap() { reset(); }

    ScopedMmap(const ScopedMmap&) = delete;
    ScopedMmap& operator=(const ScopedMmap&) = delete;
    ScopedMmap(ScopedMmap&& other) noexcept
        : ptr_(other.ptr_), len_(other.len_) {
        other.ptr_ = nullptr;
        other.len_ = 0;
    }
    ScopedMmap& operator=(ScopedMmap&& other) noexcept {
        reset();
        ptr_ = other.ptr_;
        len_ = other.len_;
        other.ptr_ = nullptr;
        other.len_ = 0;
        return *this;
    }

    void* get() const { return ptr_; }
    template <class T>
    T* as() const { return static_cast<T*>(ptr_); }
    size_t size() const { return len_; }
    bool valid() const { return ptr_ != nullptr; }
    explicit operator bool() const { return valid(); }

    void* release() {
        void* p = ptr_;
        ptr_ = nullptr;
        len_ = 0;
        return p;
    }
    void reset() {
        if (ptr_) sys::munmap(ptr_, len_);
        ptr_ = nullptr;
        len_ = 0;
    }

private:
    void* ptr_ = nullptr;
    size_t len_ = 0;
};

// Anonymous RW scratch region — common case.
inline ScopedMmap scratch_mmap(size_t len) {
    return ScopedMmap(len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS);
}

} // namespace sls
