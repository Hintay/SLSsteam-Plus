#pragma once

#include "versiontypes.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

// Outbound counterpart to IpcDispatch. Where IpcDispatch keys INBOUND interception on the
// funcHash carried in the IPC packet, this resolves the vtable index of an OUTBOUND call from
// the same build-stable funcHash — by scanning the live vtable in-process for the wrapper that
// embeds it. This makes SLSsteam's own IClient* calls immune to vtable-index drift: the only
// fragile input was the hardcoded vtable index, and funcHash replaces it.
namespace IpcOutbound
{
	// Test whether the 12 bytes at p are an embedded-funcHash mov:
	//   C7 45 ?? II II II II 6A 04 50 57 E8
	//   (mov [ebp+disp8], imm32 ; push 4 ; push eax ; push edi ; call serialize ; II.. = LE imm32)
	// On match, sets out to the imm32 and returns true. The CALLER must guarantee at least 12 bytes
	// are readable at p. This is the single source of truth for the mov shape: firstFuncHash (below)
	// and the resolver's full-.text scan both go through it, so the smoke test exercises the real
	// predicate. Inline + dependency-free so it stays host-testable without linking the resolver.
	inline bool matchFuncHashMov(const uint8_t* p, uint32_t& out)
	{
		if (p[0]  != 0xC7 || p[1] != 0x45 ||
		    p[7]  != 0x6A || p[8] != 0x04 || p[9] != 0x50 ||
		    p[10] != 0x57 || p[11] != 0xE8)
			return false;
		out = static_cast<uint32_t>(p[3])
		    | (static_cast<uint32_t>(p[4]) << 8)
		    | (static_cast<uint32_t>(p[5]) << 16)
		    | (static_cast<uint32_t>(p[6]) << 24);
		return true;
	}

	// Scan a wrapper's code bytes for the first embedded IPC funcHash constant (see matchFuncHashMov
	// for the shape). The first such constant in a wrapper is its funcHash (the second is the
	// fencepost). Sets out to the imm32 of the first match in [p, p+n) and returns true; false if none.
	inline bool firstFuncHash(const uint8_t* p, size_t n, uint32_t& out)
	{
		if (!p || n < 12) return false;
		for (size_t i = 0; i + 12 <= n; ++i)
			if (matchFuncHashMov(p + i, out))
				return true;
		return false;
	}

	// Resolve a method's vtable index from its build-stable funcHash, by locating the CLIENT-side
	// serialize wrapper (the only place the funcHash is embedded) in steamclient's .text, finding
	// the client wrapper-vtable slot that points into it, and walking back to method0. The index
	// is identical on the client wrapper vtable and the server-side `g_pClient*` vtable SLSsteam
	// actually calls, so callers apply it to their `g_pClient*` directly. Returns -1 on miss.
	//
	// The (name, bakedHash) overload tries bakedHash first; on miss, looks up name in the online
	// IpcHashes overrides (set by setOnlineHashes) and retries with the updated hash.
	//
	// Does NOT take the interface pointer: the server-side vtable (what SLSsteam holds) does NOT
	// embed the funcHash — only the client wrapper does — so resolution scans the module, not the
	// interface. NOT cached and not lock-free; callers cache the result once in a function-local
	// `static const int` (a one-time ~module scan), making the hot path a lock-free read.
	int resolveIndex(uint32_t funcHash);
	int resolveIndex(const char* name, uint32_t bakedHash);

	void setOnlineHashes(const std::map<std::string, std::vector<VersionedHash>>& hashes);

	// Pre-build segment, mov, and slot caches on the calling thread (single-threaded init).
	// Subsequent resolveIndex calls only do O(1) lookups under the lock.
	void warmup();

	// Check whether a funcHash mov exists in the scanned .text (requires warmup() first).
	bool hasHash(uint32_t funcHash);

	// Invoke vtable[index](this, args...) at an already-resolved index. Pair with a call-site
	// cached resolve (no hardcoded fallback):
	//   static const int idx = IpcOutbound::resolveIndex(funcHash);
	//   if (idx < 0) return {};                       // resolve miss -> skip the call
	//   return IpcOutbound::callAt<Sig>(idx, this, args...);
	template <typename tFN, typename... Args>
	auto callAt(int index, void* thisPtr, Args... args)
	{
		const auto fn = reinterpret_cast<tFN>((*reinterpret_cast<void***>(thisPtr))[index]);
		return fn(thisPtr, args...);
	}
}
