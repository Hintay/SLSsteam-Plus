#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

namespace CloudSaves {
// Lowercase 40-char hex SHA-1 of the buffer.
std::string Sha1Hex(const uint8_t* data, size_t len);
}
