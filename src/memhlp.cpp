#include "memhlp.hpp"

#include "log.hpp"
#include "utils.hpp"

#include "libmem/libmem.h"

#include <cstdlib>
#include <map>
#include <set>
#include <vector>

// patternToBytes and matchInBuffer live in src/memhlp_pure.cpp so they can be
// linked into smoke tests without pulling in libmem / g_pLog / Utils.

std::vector<lm_address_t> MemHlp::patternScanAll(const char* pattern, lm_module_t targetModule)
{
	const auto bytes = patternToBytes(pattern);

	static std::map<lm_address_t, lm_address_t> cachedSegments;
	static bool segsCached = false;
	if (!segsCached)
	{
		const auto enumSegments = [](lm_segment_t* seg, lm_void_t* arg) -> lm_bool_t
		{
			auto rSegments = reinterpret_cast<std::map<lm_address_t, lm_address_t>*>(arg);
			if (seg->prot & LM_PROT_XR)
				(*rSegments)[seg->base] = seg->base + seg->size;
			return LM_TRUE;
		};
		LM_EnumSegments(enumSegments, &cachedSegments);
		segsCached = true;
	}

	std::vector<lm_address_t> matches;
	for (const auto& itm : cachedSegments)
	{
		if (targetModule.base > itm.second)
			continue;
		if (targetModule.base + targetModule.size < itm.first)
			continue;
		const auto* buf = reinterpret_cast<const uint8_t*>(itm.first);
		const size_t len = itm.second - itm.first;
		for (size_t off : matchInBuffer(bytes, buf, len))
			matches.push_back(itm.first + off);
	}
	return matches;
}

lm_address_t MemHlp::searchSignature(const char* name, const char* signature, lm_module_t module, SigFollowMode mode, void* extraData, size_t extraDataSize)
{
	const auto matches = patternScanAll(signature, module);
	if (matches.empty())
	{
		g_pLog->debug("Unable to find signature for %s!\n", name);
		return LM_ADDRESS_BAD;
	}

	// Resolve each raw match through the follow mode, then require the resolved
	// targets to agree. Many call-sites that all resolve to the same function
	// (common with Relative) are NOT ambiguous; matches resolving to different
	// addresses are, and are rejected.
	std::set<lm_address_t> resolved;
	for (lm_address_t address : matches)
	{
		switch (mode)
		{
			case SigFollowMode::Relative:
				address = MemHlp::getJmpTarget(address);
				break;

			case SigFollowMode::PrologueUpwards:
				address = MemHlp::findPrologue(address, static_cast<lm_byte_t*>(extraData), extraDataSize);
				break;

			default:
				break;
		}

		if (address != LM_ADDRESS_BAD)
			resolved.insert(address);
	}

	if (resolved.size() == 1)
	{
		const lm_address_t address = *resolved.begin();
		g_pLog->debug("%s at %p\n", name, address);
		return address;
	}

	g_pLog->debug("%s: %zu raw matches resolved to %zu distinct targets, rejecting (%s)\n",
		name, matches.size(), resolved.size(),
		resolved.empty() ? "all resolutions failed" : "ambiguous");
	return LM_ADDRESS_BAD;
}

lm_address_t MemHlp::searchSignature(const char* name, const char* signature, lm_module_t module, SigFollowMode mode)
{
	return MemHlp::searchSignature(name, signature, module, mode, nullptr, 0);
}

lm_address_t MemHlp::searchSignature(const char* name, const char* signature, lm_module_t module)
{
	return searchSignature(name, signature, module, SigFollowMode::None);
}

lm_address_t MemHlp::getJmpTarget(lm_address_t address)
{
	lm_inst_t inst;
	if (!LM_Disassemble(address, &inst)) //Should not happen if we land in a code section
	{
		g_pLog->debug("Failed to disassemble code at %p!");
		return LM_ADDRESS_BAD;
	}

	g_pLog->debug("Resolved to %s %s\n", inst.mnemonic, inst.op_str);

	if (strcmp(inst.mnemonic, "jmp") != 0 && strcmp(inst.mnemonic, "call") != 0)
		return LM_ADDRESS_BAD;

	// Indirect jmp/call (e.g. "call eax", "jmp dword [reg]") have a non-numeric
	// op_str. std::stoul would throw std::invalid_argument, and that exception
	// would escape Patterns::init into the LD_AUDIT la_objopen C callback ->
	// std::terminate. strtoul never throws: it leaves endp == op_str on no
	// conversion, which we treat as "not a direct target".
	char* endp = nullptr;
	const unsigned long target = std::strtoul(inst.op_str, &endp, 16);
	if (endp == inst.op_str || *endp != '\0' || target == 0)
		return LM_ADDRESS_BAD;

	return static_cast<lm_address_t>(target);
}

lm_address_t MemHlp::findPrologue(lm_address_t address, lm_byte_t* prologueBytes, lm_size_t prologueSize)
{
	constexpr unsigned int scanSize = 0x10000;

	for(unsigned int i = 0u; i < scanSize; i++)
	{
		bool found = true;
		for(unsigned int j = 0u; j < prologueSize; j++)
		{
			if (*reinterpret_cast<lm_byte_t*>(address - i - j) != prologueBytes[j])
			{
				found = false;
				break;
			}
		}

		if (found)
		{
			lm_address_t prol = address - i - prologueSize + 1; //Add 1 byte back since bytesSize would be to big otherwise
			g_pLog->debug("Prologue found at %p\n", prol);
			return prol;
		}
	}

	g_pLog->debug("Unable to find prologue after going up %p bytes!\n", scanSize);
	return LM_ADDRESS_BAD;
}

bool MemHlp::fixPICThunkCall(const char* name, lm_address_t fn, lm_address_t tramp)
{
	g_pLog->debug("Fixing PIC thunks for %s's trampoline\n", name);
	constexpr unsigned int maxBytes = 0x5; //Minimum bytes needed to detour a function, so our tramp will at least be of this size
	
	lm_inst_t inst;
	for(unsigned int curTrampOffset = 0; curTrampOffset <= maxBytes; )
	{
		lm_address_t startAddress = tramp + curTrampOffset;

		if (!LM_Disassemble(startAddress, &inst))
		{
			g_pLog->debug("Unable to dissassemble code at %p\n", tramp + curTrampOffset);
			return false;
		}
		
		curTrampOffset += inst.size;
		g_pLog->debug("%p: %s %s\n", inst.address, inst.mnemonic, inst.op_str);
		
		if (strcmp(inst.mnemonic, "call") != 0)
			continue;

		//Calculate the call address manually with it's original location
		lm_address_t followAddress = fn + curTrampOffset + *reinterpret_cast<lm_address_t*>(startAddress + 1);
		bool isIPCThunk = true;
		char newInstr[sizeof(inst.mnemonic) + sizeof(inst.op_str)];

		for(unsigned int i = 0; i < 2; i++) //Dissassemble next 2 instructions and check if they're an actual IPC thunk call
		{
			if (!LM_Disassemble(followAddress, &inst))
			{
				g_pLog->debug("Unable to dissassemble code at %p\n", followAddress);
				return false;
			}

			followAddress += inst.size;

			g_pLog->debug("%p: %s %s\n", inst.address, inst.mnemonic, inst.op_str);

			//Can not declare in switch statement
			auto splits = std::vector<std::string>();
			lm_address_t retAddress = LM_ADDRESS_BAD;
			switch(i)
			{
				case 0:
					if (strcmp(inst.mnemonic, "mov") != 0)
						isIPCThunk = false;
					
					splits = Utils::strsplit(inst.op_str, ","); //Not checking for splits.size() since mov NEEDS a , somewhere
					retAddress = fn + curTrampOffset; //No need to add any bytes here, since i += inst.size in the outer loop takes care of that
					sprintf(newInstr, "%s %s, %p", inst.mnemonic, splits.at(0).c_str(), reinterpret_cast<void*>(retAddress));
					break;

				case 1:
					if (strcmp(inst.mnemonic, "ret") != 0)
						isIPCThunk = false;
					break;
			}

			if (!isIPCThunk)
				break;
		}

		if (!isIPCThunk)
			continue;

		if(!LM_Assemble(newInstr, &inst))
		{
			printf("Unable to assemble instruction %s!\n", newInstr);
			return false;
		}

		lm_prot_t oldProt;
		LM_ProtMemory(startAddress, inst.size, LM_PROT_XRW, &oldProt);
		LM_WriteMemory(startAddress, inst.bytes, inst.size);
		LM_ProtMemory(startAddress, inst.size, oldProt, nullptr);
		g_pLog->debug("Replaced PIC thunk call for %s at %p with %s\n", name, followAddress, newInstr);
		return true;
	}

	return false;
}


const char* MemHlp::getTypeName(void* pClass)
{
	const lm_address_t vft = *reinterpret_cast<lm_address_t*>(pClass);
	const lm_address_t typeInfo = *reinterpret_cast<lm_address_t*>(vft - sizeof(lm_address_t));
	const char* name = *reinterpret_cast<const char**>(typeInfo + sizeof(lm_address_t));

	return name;
}
