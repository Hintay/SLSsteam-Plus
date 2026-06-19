#pragma once

#include "memhlp.hpp"
#include "libmem/libmem.h"

#include <string>
#include <vector>

struct Pattern_t
{
public:
	const std::string name;
	const std::vector<std::string> candidates;   // tried in order; first that resolves wins
	const MemHlp::SigFollowMode followMode;
	std::vector<uint8_t> prologue;
	const bool optional;

	lm_module_t* module;
	lm_address_t address;

	Pattern_t(const char* name, std::vector<std::string> candidates,
	          MemHlp::SigFollowMode followMode, std::vector<uint8_t> prologue = {},
	          lm_module_t* module = nullptr, bool optional = false);

	bool find();

	// Retry resolution using online-provided candidates/follow/prologue (phase 2).
	bool findWith(const std::vector<std::string>& cands,
	              MemHlp::SigFollowMode mode, std::vector<uint8_t> prologueBytes);
};

namespace Patterns
{
	// Meyers singleton: registry constructed before any Pattern_t ctor runs,
	// regardless of translation-unit init order.
	std::vector<Pattern_t*>& registry();
	bool init();
}

#include "patterns.gen.hpp"   // generated extern Pattern_t declarations
