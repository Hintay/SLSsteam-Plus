// Standalone smoke test for MemHlp::matchInBuffer — pure byte matching with
// wildcards, no libmem / process memory. Built with g++ -m32 like other smokes.
#include "../../src/memhlp.hpp"
#include <cassert>
#include <cstdio>
#include <vector>

int main()
{
    const std::vector<uint8_t> buf = {
        0x00, 0x90, 0x11, 0xCD, 0x00,   // match at offset 1
        0x90, 0x22, 0xCD,               // match at offset 5
        0x90, 0x33, 0xEE,               // NO match (EE != CD)
    };
    auto bytes = MemHlp::patternToBytes("90 ? CD");
    auto hits = MemHlp::matchInBuffer(bytes, buf.data(), buf.size());
    assert(hits.size() == 2);
    assert(hits[0] == 1);
    assert(hits[1] == 5);

    auto uniqBytes = MemHlp::patternToBytes("11 CD");
    auto uniq = MemHlp::matchInBuffer(uniqBytes, buf.data(), buf.size());
    assert(uniq.size() == 1 && uniq[0] == 2);

    printf("pattern_smoke OK\n");
    return 0;
}
