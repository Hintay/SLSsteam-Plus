#pragma once
#include <cstdint>
#include <string>

namespace CloudSaves {
// Parse one /proc/net/tcp data line: extract the local port and socket inode.
// Returns false for the header line or malformed input.
bool ParseProcTcpLine(const std::string& line, uint16_t& localPort, uint64_t& inode);

// True if the TCP peer whose *source* port is peerPort belongs to our own PID
// (i.e. the connection came from Steam's HTTP client in this process). Scans
// /proc/net/tcp + /proc/net/tcp6 then /proc/self/fd. Returns true on lookup
// failure only if allowOnRaceFailure is set (used with a short retry).
bool PeerIsOwnProcess(uint16_t peerPort);
}
