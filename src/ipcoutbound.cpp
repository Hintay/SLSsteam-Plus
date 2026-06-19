#include "ipcoutbound.hpp"

#include "globals.hpp"       // g_modSteamClient
#include "log.hpp"           // g_pLog
#include "steamversion.hpp"

#include "libmem/libmem.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <mutex>
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
}

int IpcOutbound::resolveIndex(uint32_t funcHash)
{
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
	const int idx = resolveIndex(bakedHash);
	if (idx >= 0)
		return idx;

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
		if (best->hash != bakedHash)
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
		if (hc.hash == bakedHash || hc.hash == triedHash)
			continue;
		g_pLog->info("IpcOutbound: %s trying online candidate 0x%08x\n", name, hc.hash);
		const int result = resolveIndex(hc.hash);
		if (result >= 0)
			return result;
	}
	return -1;
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
