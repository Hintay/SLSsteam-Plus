#include "sha1.hpp"
#include <cstring>

namespace {
inline uint32_t rol(uint32_t v, int b) { return (v << b) | (v >> (32 - b)); }
}

namespace CloudSaves {

std::string Sha1Hex(const uint8_t* data, size_t len) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE,
             h3 = 0x10325476, h4 = 0xC3D2E1F0;
    const uint64_t bitLen = static_cast<uint64_t>(len) * 8;

    auto processChunk = [&](const uint8_t* p) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(p[i*4]) << 24) | (uint32_t(p[i*4+1]) << 16) |
                   (uint32_t(p[i*4+2]) << 8) | uint32_t(p[i*4+3]);
        for (int i = 16; i < 80; ++i)
            w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        uint32_t a=h0,b=h1,c=h2,d=h3,e=h4;
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20)      { f = (b & c) | ((~b) & d);            k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d;                       k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d);     k = 0x8F1BBCDC; }
            else             { f = b ^ c ^ d;                       k = 0xCA62C1D6; }
            uint32_t tmp = rol(a,5) + f + e + k + w[i];
            e = d; d = c; c = rol(b,30); b = a; a = tmp;
        }
        h0+=a; h1+=b; h2+=c; h3+=d; h4+=e;
    };

    size_t full = len / 64;
    for (size_t i = 0; i < full; ++i) processChunk(data + i*64);

    uint8_t tail[128];
    size_t rem = len - full*64;
    std::memcpy(tail, data + full*64, rem);
    tail[rem] = 0x80;
    size_t padLen = (rem < 56) ? 64 : 128;
    std::memset(tail + rem + 1, 0, padLen - rem - 1 - 8);
    for (int i = 0; i < 8; ++i)
        tail[padLen-1-i] = static_cast<uint8_t>((bitLen >> (8*i)) & 0xFF);
    processChunk(tail);
    if (padLen == 128) processChunk(tail + 64);

    char out[41];
    const uint32_t hs[5] = {h0,h1,h2,h3,h4};
    static const char* hex = "0123456789abcdef";
    for (int i = 0; i < 5; ++i)
        for (int j = 0; j < 4; ++j) {
            uint8_t byte = (hs[i] >> (24 - 8*j)) & 0xFF;
            out[i*8 + j*2]   = hex[byte >> 4];
            out[i*8 + j*2+1] = hex[byte & 0xF];
        }
    out[40] = '\0';
    return std::string(out, 40);
}

}  // namespace CloudSaves
