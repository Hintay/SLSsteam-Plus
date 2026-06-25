#pragma once

#include "libmem/libmem.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// Runtime self-discovery of IClient* vtable layouts in the loaded steamclient.so.
//
// Algorithm (typeinfo whitelist, validated by tools/whitelist_selfscan.py +
// tools/heuristic_stability.py against 4 builds):
//   1. Scan .data.rel.ro for vtable headers: [offset_to_top=0, typeinfo_ptr, method0->.text]
//   2. For each candidate, read the typeinfo's name field. Keep ONLY vtables whose
//      name is `<len>IClient<Foo>Map` AND IClient<Foo> is in our hardcoded interest
//      set (the SLSsteam hook surface — see vtablescan.cpp kInterestingIfaces).
//   3. Walk each selected vtable's slots; for each slot's wrapper, statically decode
//      the method name (from the lea-string preceding the first IPC-internal call)
//      and the funcHash (from the `C7 45 ?? IMM32 6A 04 50 57 E8` mov).
//
// Result: build-stable (interface, method) -> (vtable_VA, slot, funcHash) maps,
// replacing the patterns.toml `vft_index` and `func_hash` tables that used to
// be hand-maintained. RunIPCFrame addresses still come from res/patterns.toml
// byte signatures.
//
// One-time cost at startup: ~5ms typeinfo filter + ~10ms slot decode in C++.

namespace VtableScan
{
	struct Method
	{
		unsigned int slot;       // vtable index
		std::string  name;       // e.g. "InstallApp"  (NOT including iface prefix)
		uint32_t     funcHash;   // 0 if not extracted
		lm_address_t wrapperVA;
	};

	struct Interface
	{
		std::string         name;     // e.g. "IClientAppManager"
		lm_address_t        vtableVA; // address of vtable[0] in .data.rel.ro
		std::vector<Method> methods;
	};

	// Build all maps. Idempotent — subsequent calls reuse cached results.
	// Caller must ensure g_modSteamClient.base/end is populated
	// (LM_FindModule already called).
	void warmup();

	// Lookup APIs. Return nullptr / -1 on miss.
	const Interface* find(std::string_view iface);
	int slotOf(std::string_view iface, std::string_view method);

	// Diagnostic dump (Debug level) of the full discovered map.
	void dumpToLog();
}
