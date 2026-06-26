#pragma once
#include "save_store.hpp"
#include <cstdint>
#include <string>

namespace CloudSaves {

// In-process loopback HTTP server. Routes:
//   PUT /<acc>/<app>/<urlencoded-relpath>  -> store.beginStaging + write bytes
//   GET /<acc>/<app>/<urlencoded-relpath>  -> store.read
class HttpTransfer {
public:
    explicit HttpTransfer(SaveStore& store);
    ~HttpTransfer();

    bool start();                 // bind 127.0.0.1:0, spawn accept thread
    void stop();                  // join thread, close socket
    uint16_t port() const { return m_port; }
    bool running() const { return m_running; }

    // Accept loop body; invoked from the pthread thunk. Public so the
    // file-static thunk in the .cpp can call it on the instance.
    void acceptLoop();

    // When commitNotifier is set, a successful PUT calls it after staging the bytes.
    // (Unused for now — commit is driven by the RPC layer.)

private:
    SaveStore&  m_store;
    int         m_listenFd = -1;
    uint16_t    m_port = 0;
    volatile bool m_running = false;
    void* m_threadHandle = nullptr;   // pthread_t storage (opaque)
};

}  // namespace CloudSaves
