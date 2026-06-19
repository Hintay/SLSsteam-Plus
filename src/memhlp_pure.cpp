// Pure pattern-matching helpers — no libmem, no g_pLog, no OS calls.
// Extracted so the core byte-scan logic can be unit-tested in isolation
// (e.g. tools/pattern_smoke) without linking the full MemHlp stack.
#include "memhlp.hpp"

#include <cstring>
#include <cstdlib>
#include <vector>

std::vector<int16_t> MemHlp::patternToBytes(const char* pattern)
{
	auto bytes = std::vector<int16_t>();

	char* start = const_cast<char*>(pattern);
	char* end = start + strlen(pattern);

	while (start < end)
	{
		if (*start == '?')
		{
			bytes.emplace_back(-1);
		}
		else if (*start != ' ')
		{
			bytes.emplace_back(std::strtoul(start, &start, 16));
		}

		start++;
	}

	return bytes;
}

std::vector<size_t> MemHlp::matchInBuffer(const std::vector<int16_t>& bytes,
                                          const uint8_t* buf, size_t len)
{
	std::vector<size_t> hits;
	if (bytes.empty() || len < bytes.size())
		return hits;
	const size_t last = len - bytes.size();
	for (size_t i = 0; i <= last; i++)
	{
		bool found = true;
		for (size_t j = 0; j < bytes.size(); j++)
		{
			if (bytes[j] == -1)
				continue;
			if (buf[i + j] != static_cast<uint8_t>(bytes[j]))
			{
				found = false;
				break;
			}
		}
		if (found)
			hits.push_back(i);
	}
	return hits;
}
