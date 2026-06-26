#include "vtablescan.hpp"

#include "globals.hpp"
#include "log.hpp"

#include "libmem/libmem.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace
{
	// SLSsteam's IClient* VFThook surface. Keep in sync with the installVFT and
	// VtableScan::slotOf call sites in src/ — any iface name passed to slotOf
	// must appear here, or the lookup returns -1 and the hook isn't installed.
	constexpr std::array<std::string_view, 5> kInterestingIfaces {{
		"IClientAppManager",
		"IClientApps",
		"IClientCompat",
		"IClientRemoteStorage",
		"IClientUtils",
	}};

	constexpr size_t kStringMax      = 96;
	constexpr size_t kRecentLeas     = 6;
	constexpr unsigned int kMaxSlots = 250;

	struct Range { uintptr_t lo, hi; };
	std::vector<Range> g_text;
	std::vector<Range> g_rodata;

	std::vector<VtableScan::Interface>                     g_interfaces;
	std::map<std::string, size_t, std::less<>>             g_byName;

	std::atomic<bool> g_warmed {false};
	std::mutex        g_mtx;

	bool inText(uintptr_t va)
	{
		for (const auto& r : g_text)
			if (va >= r.lo && va < r.hi) return true;
		return false;
	}

	// Steam stores vtable slot values as either an absolute runtime VA (post-RELRO)
	// or a module-relative offset (pre-RELRO). Try both and return whichever lands
	// in an executable segment; 0 if neither does.
	uintptr_t resolveSlotValue(uint32_t raw)
	{
		if (inText(raw)) return raw;
		const uintptr_t lifted = static_cast<uintptr_t>(g_modSteamClient.base) + raw;
		if (inText(lifted)) return lifted;
		return 0;
	}

	bool inRodata(uintptr_t va)
	{
		for (const auto& r : g_rodata)
			if (va >= r.lo && va < r.hi) return true;
		return false;
	}

	lm_bool_t LM_CALL segCb(lm_segment_t* seg, lm_void_t*)
	{
		const uintptr_t base = static_cast<uintptr_t>(seg->base);
		const uintptr_t end  = static_cast<uintptr_t>(seg->end);
		const uintptr_t mlo  = static_cast<uintptr_t>(g_modSteamClient.base);
		const uintptr_t mhi  = mlo + g_modSteamClient.size;
		if (end <= mlo || base >= mhi) return LM_TRUE;
		if (seg->prot & LM_PROT_X) g_text.push_back({base, end});
		else if (seg->prot & LM_PROT_R) g_rodata.push_back({base, end});
		return LM_TRUE;
	}

	void buildSegs()
	{
		if (!g_text.empty() || !g_rodata.empty()) return;
		LM_EnumSegments(segCb, nullptr);
	}

	std::string readCString(uintptr_t va)
	{
		if (!inRodata(va)) return {};
		const char* p = reinterpret_cast<const char*>(va);
		std::string out;
		out.reserve(32);
		for (size_t i = 0; i < kStringMax; ++i)
		{
			const unsigned char c = static_cast<unsigned char>(p[i]);
			if (c == 0) return out;
			if (c < 0x20 || c > 0x7e) return {};
			out.push_back(static_cast<char>(c));
		}
		return {};
	}

	bool isMethodShape(std::string_view s)
	{
		if (s.size() < 2 || s.size() > 96)             return false;
		if (s.rfind("IClient", 0) == 0)                return false;
		for (char c : s)
			if (c == '/' || c == '%' || c == ' ')      return false;
		const unsigned char first = static_cast<unsigned char>(s[0]);
		if (!std::isalpha(first) && first != '_')      return false;
		return true;
	}

	// resolveSlotValue (above) requires the result to land in .text — meant for
	// vtable function-pointer slots. For typeinfo / name pointers (which point at
	// .rodata or RTTI data) we just need any in-module address. Try both forms.
	uintptr_t resolveAnyModulePtr(uint32_t raw)
	{
		const uintptr_t mlo = static_cast<uintptr_t>(g_modSteamClient.base);
		const uintptr_t mhi = mlo + g_modSteamClient.size;
		if (raw >= mlo && raw < mhi) return raw;
		const uintptr_t lifted = mlo + raw;
		if (lifted >= mlo && lifted < mhi) return lifted;
		return 0;
	}

	// Read the typeinfo at slot[-1] of a vtable. If the typeinfo's name field is
	// "<len>IClient<Foo>Map", return "IClient<Foo>"; otherwise empty string.
	// This is the deterministic whitelist gate that lets us pick the few
	// IClient*Map vtables out of the ~5800 RTTI candidates without any
	// heuristic prefilter.
	std::string typeinfoIfaceName(uintptr_t method0_va)
	{
		const uint32_t* ti_slot = reinterpret_cast<const uint32_t*>(method0_va - 4);
		const uintptr_t ti = resolveAnyModulePtr(*ti_slot);
		if (!ti) return {};
		const uint32_t* name_slot = reinterpret_cast<const uint32_t*>(ti + 4);
		const uintptr_t name_va = resolveAnyModulePtr(*name_slot);
		if (!name_va) return {};
		const std::string nm = readCString(name_va);
		if (nm.empty()) return {};
		size_t i = 0;
		size_t declared = 0;
		while (i < nm.size() && nm[i] >= '0' && nm[i] <= '9')
		{
			declared = declared * 10 + (nm[i] - '0');
			++i;
		}
		if (i == 0) return {};
		std::string_view body(nm.data() + i, nm.size() - i);
		if (body.size() != declared) return {};
		constexpr std::string_view kPrefix = "IClient";
		constexpr std::string_view kSuffix = "Map";
		if (body.size() <= kPrefix.size() + kSuffix.size())          return {};
		if (body.substr(0, kPrefix.size()) != kPrefix)               return {};
		if (body.substr(body.size() - kSuffix.size()) != kSuffix)    return {};
		return std::string(body.substr(0, body.size() - kSuffix.size()));
	}

	// PIC anchor recovery: locate `E8 imm32 ; [pop reg;] add reg, imm32` and return
	// (afterCall + imm) — the value the add leaves in the chosen register.
	uintptr_t findPicAnchor(lm_address_t funcStart, size_t scanLen)
	{
		if (!inText(funcStart)) return 0;
		const auto* base = reinterpret_cast<const uint8_t*>(funcStart);
		for (size_t i = 0; i + 11 <= scanLen; ++i)
		{
			if (base[i] != 0xE8) continue;
			const uintptr_t afterCall = static_cast<uintptr_t>(funcStart) + i + 5;
			const size_t end = std::min(i + 5 + 16, scanLen - 5);
			for (size_t j = i + 5; j < end; ++j)
			{
				if (base[j] == 0x81 && (base[j+1] & 0xF8) == 0xC0)  // add r32, imm32
				{
					int32_t imm = 0;
					std::memcpy(&imm, base + j + 2, sizeof(imm));
					return static_cast<uintptr_t>(static_cast<intptr_t>(afterCall) + imm);
				}
			}
		}
		return 0;
	}

	// Decode (method name, funcHash) for a single wrapper. Byte-level scan (no
	// LM_Disassemble in the hot loop): each lea / call / funcHash-mov has a unique
	// fixed-length signature. Returns false on no match. The iface name is taken
	// from typeinfo (caller knows it already); only the method-string lea sequence
	// preceding the first IPC-internal call matters here.
	//
	// We accept the FIRST call site where `recent` holds a method-shaped string,
	// matching the offline tools/extract_vtable_names.py behaviour. Gating on
	// `target == TraceIPC` is fragile across builds (the call may go through a
	// PLT-like thunk, or the wrapper may inline its own TraceIPC), but in every
	// IClient*Map wrapper the iface/method lea sequence sits before the first
	// call past them — so the first-with-recent rule is sufficient.
	bool decodeWrapper(lm_address_t funcStart,
	                   std::string& method, uint32_t& funcHash)
	{
		constexpr size_t kEarlyScan = 0x400;
		const uintptr_t picBase = findPicAnchor(funcStart, 0x40);
		if (picBase == 0) return false;

		const auto* base = reinterpret_cast<const uint8_t*>(funcStart);

		std::string recent[kRecentLeas];
		size_t head = 0;
		bool tipcMatched = false;
		funcHash = 0;

		for (size_t i = 0; i + 5 < kEarlyScan; ++i)
		{
			if (base[i] == 0xE8 && !tipcMatched)
			{
				for (size_t k = 0; k < kRecentLeas; ++k)
				{
					const size_t idx = (head + kRecentLeas - 1 - k) % kRecentLeas;
					const auto& s = recent[idx];
					if (s.empty()) continue;
					if (method.empty() && isMethodShape(s)) { method = s; break; }
				}
				tipcMatched = !method.empty();
			}

			if (base[i] == 0x8D && i + 6 <= kEarlyScan)
			{
				const uint8_t modrm = base[i+1];
				if ((modrm & 0xC0) == 0x80 && (modrm & 0x07) != 4)
				{
					int32_t disp = 0;
					std::memcpy(&disp, base + i + 2, sizeof(disp));
					const uintptr_t target = static_cast<uintptr_t>(
						(static_cast<uint64_t>(picBase) + static_cast<uint32_t>(disp)) & 0xFFFFFFFFu);
					std::string s = readCString(target);
					if (!s.empty())
					{
						recent[head] = std::move(s);
						head = (head + 1) % kRecentLeas;
					}
				}
			}

			// funcHash mov: C7 45 ?? IMM32 6A 04 50 57 E8
			if (funcHash == 0 && i + 12 <= kEarlyScan &&
			    base[i] == 0xC7 && base[i+1] == 0x45 &&
			    base[i+7]  == 0x6A && base[i+8]  == 0x04 &&
			    base[i+9]  == 0x50 && base[i+10] == 0x57 && base[i+11] == 0xE8)
			{
				funcHash = static_cast<uint32_t>(base[i+3])
				         | (static_cast<uint32_t>(base[i+4]) << 8)
				         | (static_cast<uint32_t>(base[i+5]) << 16)
				         | (static_cast<uint32_t>(base[i+6]) << 24);
			}

			if (tipcMatched && funcHash != 0) return true;
		}

		return tipcMatched;
	}

	// Walk .data.rel.ro for RTTI vtable headers: `[ot=0, ti!=0, slot0->.text]`.
	// Returns (slot0_va, slots[]) per candidate. Iface attribution is done later
	// via the typeinfo name read.
	std::vector<std::pair<uintptr_t, std::vector<lm_address_t>>> findCandidateVtables()
	{
		std::vector<std::pair<uintptr_t, std::vector<lm_address_t>>> out;
		for (const auto& seg : g_rodata)
		{
			for (uintptr_t p = seg.lo + 8; p + 4 <= seg.hi; p += 4)
			{
				const uint32_t raw = *reinterpret_cast<const uint32_t*>(p);
				const uintptr_t method0 = resolveSlotValue(raw);
				if (method0 == 0) continue;
				const uint32_t ti = *reinterpret_cast<const uint32_t*>(p - 4);
				const uint32_t ot = *reinterpret_cast<const uint32_t*>(p - 8);
				if (ot != 0 || ti == 0) continue;

				std::vector<lm_address_t> slots;
				slots.reserve(64);
				slots.push_back(static_cast<lm_address_t>(method0));
				for (uintptr_t q = p + 4; q + 4 <= seg.hi; q += 4)
				{
					const uint32_t v = *reinterpret_cast<const uint32_t*>(q);
					const uintptr_t resolved = resolveSlotValue(v);
					if (resolved == 0) break;
					slots.push_back(static_cast<lm_address_t>(resolved));
					if (slots.size() >= kMaxSlots) break;
				}
				if (slots.size() >= 3) out.push_back({p, std::move(slots)});
			}
		}
		return out;
	}

}


void VtableScan::warmup()
{
	if (g_warmed.load(std::memory_order_acquire)) return;
	std::lock_guard<std::mutex> lk(g_mtx);
	if (g_warmed.load(std::memory_order_relaxed)) return;

	buildSegs();
	if (g_text.empty() || g_rodata.empty())
	{
		g_pLog->warn("VtableScan: missing segments, refusing to scan (text=%zu rodata=%zu)\n",
		             g_text.size(), g_rodata.size());
		return;
	}

	const std::unordered_set<std::string_view> interest(
		kInterestingIfaces.begin(), kInterestingIfaces.end());

	auto candidates = findCandidateVtables();

	for (auto& [method0_va, slots] : candidates)
	{
		std::string iface = typeinfoIfaceName(method0_va);
		if (iface.empty() || !interest.count(std::string_view(iface))) continue;

		// Prefer the largest vtable if (somehow) multiple Map vtables exist for
		// the same iface — the production wrapper is the one with the most slots.
		auto existing = g_byName.find(iface);
		if (existing != g_byName.end() && g_interfaces[existing->second].methods.size() >= slots.size())
			continue;

		Interface rec;
		rec.name     = iface;
		rec.vtableVA = static_cast<lm_address_t>(method0_va);
		rec.methods.reserve(slots.size());
		for (size_t idx = 0; idx < slots.size(); ++idx)
		{
			std::string method;
			uint32_t fh = 0;
			decodeWrapper(slots[idx], method, fh);
			rec.methods.push_back({
				static_cast<unsigned int>(idx),
				std::move(method),
				fh,
				slots[idx],
			});
		}

		if (existing != g_byName.end())
		{
			g_interfaces[existing->second] = std::move(rec);
		}
		else
		{
			g_byName[iface] = g_interfaces.size();
			g_interfaces.push_back(std::move(rec));
		}
	}

	size_t funcHashCount = 0;
	for (const auto& iface : g_interfaces)
		for (const auto& m : iface.methods)
			if (m.funcHash) ++funcHashCount;

	g_warmed.store(true, std::memory_order_release);

	g_pLog->info("VtableScan: %zu/%zu ifaces selected (typeinfo whitelist), %zu funcHashes, %zu candidate vtables scanned\n",
	             g_interfaces.size(), kInterestingIfaces.size(), funcHashCount, candidates.size());
	dumpToLog();
}

const VtableScan::Interface* VtableScan::find(std::string_view iface)
{
	if (!g_warmed.load(std::memory_order_acquire)) return nullptr;
	auto it = g_byName.find(iface);
	if (it == g_byName.end()) return nullptr;
	return &g_interfaces[it->second];
}

int VtableScan::slotOf(std::string_view iface, std::string_view method)
{
	// Exact match only. Caller must pass Steam's internal name verbatim,
	// including any `B` prefix for bool-returning methods (e.g.
	// "BGetDLCDataByIndex", "BIsDlcEnabled") and exact letter casing
	// (e.g. "GetAppID" with capital ID, not "GetAppId"). The audit tool
	// at tools/whitelist_selfscan.py can verify name alignment offline.
	const Interface* p = find(iface);
	if (!p) return -1;
	for (const auto& m : p->methods)
		if (m.name == method)
			return static_cast<int>(m.slot);
	return -1;
}

void VtableScan::dumpToLog()
{
	if (!g_pLog) return;
	for (const auto& iface : g_interfaces)
	{
		g_pLog->debug("VtableScan: %s @ 0x%08x  slots=%zu\n",
		              iface.name.c_str(),
		              static_cast<unsigned>(iface.vtableVA),
		              iface.methods.size());
		for (const auto& m : iface.methods)
		{
			if (m.name.empty() && m.funcHash == 0) continue;
			g_pLog->debug("  [%3u] %s::%s  funcHash=0x%08x  wrapper=0x%08x\n",
			              m.slot, iface.name.c_str(),
			              m.name.empty() ? "(unresolved)" : m.name.c_str(),
			              m.funcHash, static_cast<unsigned>(m.wrapperVA));
		}
	}
}
