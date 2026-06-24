#include "ipcoutbound.hpp"

#include "globals.hpp"       // g_modSteamClient
#include "log.hpp"           // g_pLog
#include "steamversion.hpp"

#include "libmem/libmem.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace
{
	// The client wrapper's function start lies at most this far below its embedded funcHash mov.
	constexpr uintptr_t kBackRange = 0x200;

	struct Range { uintptr_t lo, hi; };
	std::vector<Range> g_text;     // steamclient executable segments (.text)
	std::vector<Range> g_rodata;   // steamclient read-only non-exec segments (vtables live here)
	uintptr_t g_textLo = 0, g_textHi = 0;  // global bounds of all .text ranges
	bool               g_segsReady = false;

	// funcHash -> address of its "C7 45 ?? <imm32> 6A 04 50 57 E8" mov in .text. Built by ONE full
	// .text pass that records every such mov, so N method resolutions share a single ~31MB scan
	// instead of one each. First occurrence of a given imm32 wins (matches the old first-match).
	std::unordered_map<uint32_t, uintptr_t> g_movByHash;
	bool g_movsScanned = false;

	// All vtable slots in steamclient's rodata, as (target function-start, slot address) pairs sorted
	// by target. Built by ONE full rodata pass that keeps every word pointing into .text whose
	// immediate neighbour is also a .text pointer (i.e. the word sits inside a vtable run, not a stray
	// code pointer). resolveIndex then binary-searches this once-built table for the slot nearest below
	// a funcHash mov, instead of rescanning all ~14MB of rodata per funcHash.
	std::vector<std::pair<uintptr_t, uintptr_t>> g_slots;
	bool g_slotsScanned = false;

	// funcHash -> resolved vtable index (or -1). Final result cache.
	std::unordered_map<uint32_t, int> g_idxByHash;

	// "IClientApps::GetAppData" -> versioned candidate funcHashes, set once from online YAML.
	std::map<std::string, std::vector<VersionedHash>> g_onlineHashes;

	struct NamePool
	{
		std::string_view iface;
		std::vector<const char*> methods;
	};
	std::vector<NamePool> g_namePools;
	bool g_namePoolsScanned = false;

	// TraceIPC's resolved runtime address, set by hooks.cpp after pattern resolution.
	// The wrapper decoder uses this to identify the call site whose preceding lea
	// instructions carry the IPC iface/method labels.
	std::atomic<uintptr_t> g_traceIpcAddr {0};

	// Serializes the one-time lazy builds (segments, mov table, slot table, index cache). resolveIndex
	// is not a hot path (called once per hooked/called method), so a coarse lock is fine and the
	// original's unsynchronized lazy init (concurrent interface seams on different IPC threads) is fixed.
	std::mutex g_mtx;

	bool inText(uintptr_t p)
	{
		if (p < g_textLo || p >= g_textHi) return false;
		for (const auto& r : g_text) if (p >= r.lo && p < r.hi) return true;
		return false;
	}

	lm_bool_t LM_CALL segCb(lm_segment_t* seg, lm_void_t*)
	{
		const uintptr_t base = static_cast<uintptr_t>(seg->base);
		const uintptr_t end  = static_cast<uintptr_t>(seg->end);
		const uintptr_t mlo  = static_cast<uintptr_t>(g_modSteamClient.base);
		const uintptr_t mhi  = mlo + g_modSteamClient.size;
		if (end <= mlo || base >= mhi) return LM_TRUE;   // outside steamclient
		if (seg->prot & LM_PROT_X)
			g_text.push_back({ base, end });
		else if ((seg->prot & LM_PROT_R) && !(seg->prot & LM_PROT_W))
			g_rodata.push_back({ base, end });
		return LM_TRUE;
	}

	void ensureSegs()
	{
		if (g_segsReady) return;
		if (!g_modSteamClient.base) return;
		LM_EnumSegments(segCb, nullptr);
		for (const auto& r : g_text)
		{
			if (!g_textLo || r.lo < g_textLo) g_textLo = r.lo;
			if (r.hi > g_textHi) g_textHi = r.hi;
		}
		g_segsReady = true;
	}

	void scanAllMovs()
	{
		if (g_movsScanned) return;
		g_movsScanned = true;
		for (const auto& seg : g_text)
		{
			const uint8_t* const end = reinterpret_cast<const uint8_t*>(seg.hi);
			for (const uint8_t* p = reinterpret_cast<const uint8_t*>(seg.lo); p + 12 <= end; ++p)
			{
				uint32_t h;
				if (IpcOutbound::matchFuncHashMov(p, h))
					g_movByHash.emplace(h, reinterpret_cast<uintptr_t>(p));   // first wins
			}
		}
	}

	// One rodata pass: collect every vtable slot (target, slot) and sort by target. A word qualifies
	// when its value points into .text AND an immediate neighbour (slot ± 4) also points into .text,
	// the same code-pointer-run test the per-funcHash scan used to reject stray rodata values.
	void scanAllSlots()
	{
		if (g_slotsScanned) return;
		g_slotsScanned = true;
		for (const auto& seg : g_rodata)
		{
			for (uintptr_t a = seg.lo; a + 4 <= seg.hi; a += 4)
			{
				const uint32_t V = *reinterpret_cast<const uint32_t*>(a);
				if (!inText(V)) continue;
				const bool nextCode = (a + 8 <= seg.hi) && inText(*reinterpret_cast<const uint32_t*>(a + 4));
				const bool prevCode = (a >= seg.lo + 4) && inText(*reinterpret_cast<const uint32_t*>(a - 4));
				if (!nextCode && !prevCode) continue;
				g_slots.emplace_back(static_cast<uintptr_t>(V), a);
			}
		}
		std::sort(g_slots.begin(), g_slots.end());
	}

	bool isPrintableAsciiString(const char* s, size_t len)
	{
		if (len < 2 || len > 96) return false;
		for (size_t i = 0; i < len; ++i)
		{
			const unsigned char c = static_cast<unsigned char>(s[i]);
			if (c < 0x20 || c > 0x7e) return false;
		}
		return true;
	}

	bool isInterfaceName(std::string_view s)
	{
		return s.rfind("IClient", 0) == 0;
	}

	void addNamePool(std::string_view iface, const std::vector<const char*>& methods)
	{
		if (iface.empty() || methods.empty()) return;
		g_namePools.push_back({ iface, methods });
	}

	void scanNamePoolsInRange(uintptr_t lo, uintptr_t hi)
	{
		std::string_view currentIface;
		std::vector<const char*> currentMethods;
		std::vector<const char*> precedingRun;

		for (uintptr_t p = lo; p < hi; )
		{
			while (p < hi && *reinterpret_cast<const char*>(p) == '\0') ++p;
			if (p >= hi) break;

			const char* const s = reinterpret_cast<const char*>(p);
			size_t len = 0;
			while (p + len < hi && s[len] != '\0') ++len;
			if (p + len >= hi)
				break;

			if (!isPrintableAsciiString(s, len))
			{
				++p;
				currentIface = {};
				currentMethods.clear();
				precedingRun.clear();
				continue;
			}

			const std::string_view sv(s, len);
			if (isInterfaceName(sv))
			{
				addNamePool(currentIface, currentMethods);      // Interface\0Method... shape.
				addNamePool(sv, precedingRun);                  // ...Method\0Interface shape.
				currentIface = sv;
				currentMethods.clear();
				precedingRun.clear();
			}
			else
			{
				if (!currentIface.empty())
					currentMethods.push_back(s);
				precedingRun.push_back(s);
				if (precedingRun.size() > 128)
					precedingRun.erase(precedingRun.begin());
			}

			p += len + 1;
		}
		addNamePool(currentIface, currentMethods);
	}

	void scanNamePools()
	{
		if (g_namePoolsScanned) return;
		g_namePoolsScanned = true;
		for (const auto& seg : g_rodata)
			scanNamePoolsInRange(seg.lo, seg.hi);
	}

	bool methodNameMatches(std::string_view actual, std::string_view expected)
	{
		return actual == expected
			|| (actual.size() == expected.size() + 1 && actual[0] == 'B' && actual.substr(1) == expected)
			|| (expected.size() == actual.size() + 1 && expected[0] == 'B' && expected.substr(1) == actual);
	}

	const char* printableRodataString(uintptr_t p)
	{
		for (const auto& seg : g_rodata)
		{
			if (p < seg.lo || p >= seg.hi)
				continue;

			const char* const s = reinterpret_cast<const char*>(p);
			size_t len = 0;
			while (p + len < seg.hi && s[len] != '\0')
				++len;
			if (p + len >= seg.hi || !isPrintableAsciiString(s, len))
				return nullptr;
			return s;
		}
		return nullptr;
	}

	bool isKnownMethodForInterface(std::string_view iface, std::string_view method)
	{
		for (const auto& pool : g_namePools)
		{
			if (pool.iface != iface)
				continue;
			for (const char* candidate : pool.methods)
			{
				const std::string_view known(candidate, std::strlen(candidate));
				if (methodNameMatches(method, known))
					return true;
			}
		}
		return false;
	}

	bool isUsableMethodCandidate(std::string_view s)
	{
		if (s.empty())                                        return false;
		if (isInterfaceName(s))                               return false;
		if (s.find('/') != std::string_view::npos)            return false;
		if (s.find('%') != std::string_view::npos)            return false;
		if (s.find(' ') != std::string_view::npos)            return false;
		return true;
	}

	// Decode the actual method name from a wrapper function's prologue by anchoring on
	// its `call TraceIPC` instruction.
	//
	// Each Steam IClient method wrapper opens with a `TraceIPC(iface, method)` call
	// where both string arguments are loaded via `lea reg, [picBase + disp32]` shortly
	// before the call. We:
	//   1. Recover picBase from the wrapper's PIC anchor (E8 imm32 ; [pop reg;] add reg, imm32).
	//   2. Walk forward with proper instruction stepping, keeping a ring buffer of the
	//      last few lea-loaded printable strings.
	//   3. On encountering `call rel32` whose target equals TraceIPC's runtime address,
	//      return the most recent non-interface-name string in the ring buffer.
	//
	// Returns nullptr if the wrapper does not match the expected shape (no PIC anchor,
	// no TraceIPC call within the scan window, or no method-shaped string in the recent
	// lea history). Callers MUST treat nullptr as "no signal" and let the dynamic
	// TraceIPC hook arbitrate, never as a mismatch.
	const char* resolveWrapperInternalName(std::string_view /*expectedIface*/, std::string_view /*expectedMethod*/, uintptr_t functionAddress)
	{
		if (!functionAddress || !inText(functionAddress))
			return nullptr;

		const uintptr_t traceIpc = g_traceIpcAddr.load(std::memory_order_relaxed);
		if (traceIpc == 0)
			return nullptr;

		constexpr uintptr_t kWrapperScanRange = 0x400;
		uintptr_t picBase = 0;
		int picReg = -1;
		const uintptr_t scanEnd = functionAddress + kWrapperScanRange;

		// PIC anchor: call $+5; [pop reg;] add reg, imm32.  The same expression in both
		// gcc (get_pc_thunk) and clang (inline) forms — after the add, the register
		// holds (afterCall + imm32). Byte scan is fine here: the pattern is fixed.
		for (uintptr_t p = functionAddress; p + 11 <= scanEnd; ++p)
		{
			const auto* b = reinterpret_cast<const uint8_t*>(p);
			if (b[0] != 0xE8)
				continue;

			const uintptr_t afterCall = p + 5;
			for (uintptr_t q = afterCall; q + 6 <= afterCall + 16 && q + 6 <= scanEnd; ++q)
			{
				const auto* a = reinterpret_cast<const uint8_t*>(q);
				if (a[0] == 0x81 && (a[1] & 0xF8) == 0xC0) // add r32, imm32
				{
					picReg = a[1] & 0x07;
					int32_t imm = 0;
					std::memcpy(&imm, a + 2, sizeof(imm));
					picBase = static_cast<uintptr_t>(static_cast<intptr_t>(afterCall) + imm);
					break;
				}
			}
			if (picReg >= 0)
				break;
		}
		(void)picReg;  // We no longer filter on the register — any copy holds the same picBase value.

		if (picBase == 0)
		{
			g_pLog->debug("resolveWrapperInternalName(0x%08x): PIC anchor not found\n",
			              static_cast<unsigned>(functionAddress));
			return nullptr;
		}

		// Walk instructions properly so a 0x8D / 0xE8 byte inside another instruction's
		// operands does not get mis-decoded. Maintain a small ring buffer of recently
		// observed lea-resolved strings.
		constexpr size_t kRecent = 6;
		const char* recent[kRecent] = { nullptr };
		size_t recentHead = 0;  // next write slot

		lm_address_t cursor = functionAddress;
		size_t leaCount = 0;
		while (cursor < scanEnd)
		{
			lm_inst_t inst {};
			if (!LM_Disassemble(cursor, &inst))
				break;

			if (std::strcmp(inst.mnemonic, "call") == 0 &&
			    inst.size == 5 && inst.bytes[0] == 0xE8)
			{
				int32_t rel = 0;
				std::memcpy(&rel, &inst.bytes[1], sizeof(rel));
				const uintptr_t target = static_cast<uintptr_t>(
					(static_cast<uint64_t>(inst.address) + 5u + static_cast<uint32_t>(rel)) & 0xFFFFFFFFu);

				if (target == traceIpc)
				{
					// Pull the most recent interface name and the most recent method-shaped
					// string from the ring buffer. These are the two `TraceIPC(iface, method)`
					// arguments loaded immediately before this call.
					const char* iface  = nullptr;
					const char* method = nullptr;
					for (size_t k = 0; k < kRecent; ++k)
					{
						const size_t i = (recentHead + kRecent - 1 - k) % kRecent;
						if (!recent[i]) continue;
						const std::string_view sv(recent[i], std::strlen(recent[i]));
						if (isInterfaceName(sv))
						{
							if (!iface) iface = recent[i];
						}
						else if (isUsableMethodCandidate(sv))
						{
							if (!method) method = recent[i];
						}
						if (iface && method) break;
					}

					if (!iface || !method)
					{
						g_pLog->debug("resolveWrapperInternalName(0x%08x): TraceIPC call found but iface/method missing (iface=%s method=%s leas=%zu)\n",
						              static_cast<unsigned>(functionAddress),
						              iface ? iface : "(null)", method ? method : "(null)", leaCount);
						return nullptr;
					}

					// Synthesize "iface::method" once per wrapper and cache so the
					// returned pointer is stable across subsequent calls.
					static std::mutex s_cacheMtx;
					static std::unordered_map<uintptr_t, std::string> s_cache;
					std::lock_guard<std::mutex> lk(s_cacheMtx);
					auto& slot = s_cache[functionAddress];
					if (slot.empty())
					{
						slot.assign(iface);
						slot.append("::");
						slot.append(method);
					}
					return slot.c_str();
				}
			}
			else if (std::strcmp(inst.mnemonic, "lea") == 0 &&
			         inst.size >= 6 && inst.bytes[0] == 0x8D &&
			         (inst.bytes[1] & 0xC0) == 0x80 &&
			         (inst.bytes[1] & 0x07) != 4)
			{
				int32_t disp = 0;
				std::memcpy(&disp, &inst.bytes[2], sizeof(disp));
				const uintptr_t target = static_cast<uintptr_t>(
					(static_cast<uint64_t>(picBase) + static_cast<uint32_t>(disp)) & 0xFFFFFFFFu);
				const char* s = printableRodataString(target);
				if (s)
				{
					recent[recentHead] = s;
					recentHead = (recentHead + 1) % kRecent;
					++leaCount;
				}
			}

			cursor += inst.size;
		}

		g_pLog->debug("resolveWrapperInternalName(0x%08x): TraceIPC@0x%08x not seen within 0x%lx bytes (leas=%zu picBase=0x%08x)\n",
		              static_cast<unsigned>(functionAddress), static_cast<unsigned>(traceIpc),
		              static_cast<unsigned long>(kWrapperScanRange),
		              leaCount, static_cast<unsigned>(picBase));
		return nullptr;
	}
}

int IpcOutbound::resolveIndex(uint32_t funcHash)
{
	if (funcHash == 0)
		return -1;

	std::lock_guard<std::mutex> lk(g_mtx);

	ensureSegs();
	if (g_text.empty() || g_rodata.empty()) return -1;

	if (const auto it = g_idxByHash.find(funcHash); it != g_idxByHash.end())
		return it->second;

	// 1) Locate the wrapper's funcHash mov in .text (single shared scan, then O(1) lookup).
	scanAllMovs();
	const auto mi = g_movByHash.find(funcHash);
	if (mi == g_movByHash.end())
	{
		g_pLog->debug("IpcOutbound: funcHash 0x%08x mov not found in .text\n", funcHash);
		return g_idxByHash[funcHash] = -1;
	}
	const uintptr_t M = mi->second;

	// 2) The vtable slot is the rodata word whose value (a wrapper function start) is the LARGEST
	//    address in [M-kBackRange, M] — the function that contains M. Binary-search the once-built
	//    slot table (already neighbour-validated) for the largest target <= M, bounded below by M-kBackRange.
	scanAllSlots();
	const uintptr_t lo = M - kBackRange;
	auto it = std::upper_bound(g_slots.begin(), g_slots.end(),
	                           std::make_pair(M, std::numeric_limits<uintptr_t>::max()));
	if (it == g_slots.begin() || (--it)->first < lo)
	{
		g_pLog->debug("IpcOutbound: funcHash 0x%08x slot not found near 0x%08x\n",
		              funcHash, static_cast<unsigned>(M));
		return g_idxByHash[funcHash] = -1;
	}
	// Among slots sharing the max target, take the lowest address (matches the old ascending scan).
	const uintptr_t bestTarget = it->first;
	while (it != g_slots.begin() && std::prev(it)->first == bestTarget) --it;
	const uintptr_t bestSlot = it->second;

	uintptr_t bestSegLo = 0;
	for (const auto& seg : g_rodata)
		if (bestSlot >= seg.lo && bestSlot < seg.hi) { bestSegLo = seg.lo; break; }

	// 3) Walk back to method0 (first slot of the contiguous .text-pointer run) -> index.
	uintptr_t cur = bestSlot;
	while (cur - 4 >= bestSegLo && inText(*reinterpret_cast<const uint32_t*>(cur - 4)))
		cur -= 4;
	return g_idxByHash[funcHash] = static_cast<int>((bestSlot - cur) / 4);
}

int IpcOutbound::resolveIndex(const char* name, uint32_t bakedHash)
{
	if (bakedHash != 0)
	{
		const int idx = resolveIndex(bakedHash);
		if (idx >= 0)
			return idx;
	}

	std::vector<VersionedHash> candidates;
	{
		std::lock_guard<std::mutex> lk(g_mtx);
		const auto it = g_onlineHashes.find(name);
		if (it == g_onlineHashes.end())
			return -1;
		candidates = it->second;
	}

	const uint32_t ver = SteamVersion::get();
	uint32_t triedHash = bakedHash;

	// Version-based: try the best match first, then fall through to all candidates.
	if (const auto* best = pickByVersion(candidates, ver))
	{
		if (best->hash != 0 && best->hash != bakedHash)
		{
			triedHash = best->hash;
			g_pLog->info("IpcOutbound: %s baked 0x%08x missed, version %u -> online 0x%08x\n",
			             name, bakedHash, ver, best->hash);
			const int result = resolveIndex(best->hash);
			if (result >= 0)
				return result;
		}
	}

	// Fallback: version unavailable, version pick failed, or picked hash not in binary.
	for (const auto& hc : candidates)
	{
		if (hc.hash == 0 || hc.hash == bakedHash || hc.hash == triedHash)
			continue;
		g_pLog->info("IpcOutbound: %s trying online candidate 0x%08x\n", name, hc.hash);
		const int result = resolveIndex(hc.hash);
		if (result >= 0)
			return result;
	}
	return -1;
}

const char* IpcOutbound::resolveStaticInternalName(const char* expectedFullName, unsigned int index, uintptr_t functionAddress)
{
	if (!expectedFullName)
		return nullptr;

	const std::string_view expected(expectedFullName);
	const size_t sep = expected.find("::");
	if (sep == std::string_view::npos)
		return nullptr;

	const std::string_view expectedIface = expected.substr(0, sep);
	const std::string_view expectedMethod = expected.substr(sep + 2);

	std::lock_guard<std::mutex> lk(g_mtx);
	ensureSegs();
	if (g_rodata.empty())
		return nullptr;

	// Only the wrapper-body decode is trustworthy. The previous .rodata name-pool
	// fallback was unreliable: pool order rarely matches the C++ vtable order, so
	// matching by index gave false positives that the dynamic TraceIPC check then
	// had to undo. Returning nullptr here means "unknown" -> caller installs and
	// dynamic check arbitrates at first call.
	(void)index;
	return resolveWrapperInternalName(expectedIface, expectedMethod, functionAddress);
}

void IpcOutbound::setTraceIpcAddr(uintptr_t addr)
{
	g_traceIpcAddr.store(addr, std::memory_order_relaxed);
}

void IpcOutbound::setOnlineHashes(const std::map<std::string, std::vector<VersionedHash>>& hashes)
{
	std::lock_guard<std::mutex> lk(g_mtx);
	g_onlineHashes = hashes;
}

void IpcOutbound::warmup()
{
	std::lock_guard<std::mutex> lk(g_mtx);
	ensureSegs();
	if (!g_text.empty())
	{
		scanAllMovs();
		scanAllSlots();
	}
}

bool IpcOutbound::hasHash(uint32_t funcHash)
{
	std::lock_guard<std::mutex> lk(g_mtx);
	// Scan .text for funcHash movs without caching segments — ensureSegs would
	// latch the segment map at a point where .data.rel.ro is still RW (before
	// RELRO), poisoning the rodata cache for later resolveIndex calls.
	if (!g_movsScanned && g_modSteamClient.base)
	{
		std::vector<Range> textSegs;
		const auto cb = [](lm_segment_t* seg, lm_void_t* arg) -> lm_bool_t
		{
			auto* out = reinterpret_cast<std::vector<Range>*>(arg);
			const uintptr_t base = static_cast<uintptr_t>(seg->base);
			const uintptr_t end  = static_cast<uintptr_t>(seg->end);
			const uintptr_t mlo  = static_cast<uintptr_t>(g_modSteamClient.base);
			const uintptr_t mhi  = mlo + g_modSteamClient.size;
			if (end <= mlo || base >= mhi) return LM_TRUE;
			if (seg->prot & LM_PROT_X)
				out->push_back({ base, end });
			return LM_TRUE;
		};
		LM_EnumSegments(cb, &textSegs);
		for (const auto& seg : textSegs)
		{
			const uint8_t* const end = reinterpret_cast<const uint8_t*>(seg.hi);
			for (const uint8_t* p = reinterpret_cast<const uint8_t*>(seg.lo); p + 12 <= end; ++p)
			{
				uint32_t h;
				if (IpcOutbound::matchFuncHashMov(p, h))
					g_movByHash.emplace(h, reinterpret_cast<uintptr_t>(p));
			}
		}
		g_movsScanned = true;
	}
	return g_movByHash.count(funcHash) > 0;
}
