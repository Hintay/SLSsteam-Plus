#pragma once

#include "libmem/libmem.h"
#include "log.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>


namespace MemHlp
{
	enum class SigFollowMode
	{
		None,
		Relative,
		PrologueUpwards
	};

	///Summary:
	///Write assembly code to address and increase address by bytes written
	template<typename ...Args>
	bool assembleCodeAt(lm_address_t& address, const char* fmt, Args... args)
	{
		if (address == LM_ADDRESS_BAD)
		{
			g_pLog->debug("Can't write to LM_ADDRESS_BAD!\n");
			return false;
		}

		size_t size = snprintf(nullptr, 0, fmt, args...) + 1;
		char* code = reinterpret_cast<char*>(malloc(size));
		snprintf(code, size, fmt, args...);

		static lm_inst_t inst;
		//TODO: Potentially replace with LM_AssembleEx and only allocate memory as needed
		bool success = false;

		if (!LM_Assemble(code, &inst))
		{
			g_pLog->debug("Failed to assemble %s!\n", code);
		}
		else if (!LM_WriteMemory(address, inst.bytes, inst.size))
		{
			g_pLog->debug("Failed to write %s to %p!\n", code, address);
		}
		else
		{
			g_pLog->debug("Wrote %s to %p with %i bytes\n", code, address, inst.size);
			address += inst.size;
			success = true;
		}

		free(code);
		return success;
	}

	std::vector<int16_t> patternToBytes(const char* pattern);

	// Pure wildcard byte search over a flat buffer. Returns every match offset.
	// -1 entries in `bytes` (from patternToBytes) are wildcards. Extracted so the
	// matching core is unit-testable without libmem / live process memory.
	std::vector<size_t> matchInBuffer(const std::vector<int16_t>& bytes,
	                                  const uint8_t* buf, size_t len);

	// Returns every raw match address in the module's executable segments.
	// Ambiguity is resolved by searchSignature on the *follow-resolved* targets,
	// not the raw count: many call-sites resolving to one function are unique.
	std::vector<lm_address_t> patternScanAll(const char* pattern, lm_module_t module);

	lm_address_t searchSignature(const char* name, const char* signature, lm_module_t module, SigFollowMode mode, void* extraData, size_t extraDataSize);
	lm_address_t searchSignature(const char* name, const char* signature, lm_module_t module, SigFollowMode mode);
	lm_address_t searchSignature(const char* name, const char* signature, lm_module_t module);

	lm_address_t getJmpTarget(lm_address_t address);
	lm_address_t findPrologue(lm_address_t address, lm_byte_t* prologueBytes, lm_size_t prologueSize);

	//TODO: Create hooking wrapper that calls this automatically
	bool fixPICThunkCall(const char* name, lm_address_t fn, lm_address_t tramp);

	const char* getTypeName(void* pClass);
}
