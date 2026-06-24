#include "driftreport.hpp"

#include "log.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{
	enum class Kind
	{
		VFTStatic,
		VFTDynamic,
		PatternMissing,
	};

	struct Entry
	{
		Kind kind;
		std::string name;
		unsigned int index;   // VFTStatic
		std::string expected;
		std::string actual;
		bool optional;        // PatternMissing
	};

	std::mutex g_mtx;
	std::vector<Entry> g_entries;
	std::atomic_bool g_scheduled {false};

	void emit(std::vector<Entry>&& batch);

	void schedule()
	{
		// Single deferred flush; re-armable after each emit so late-arriving
		// drift (e.g., a dynamic TraceIPC mismatch fired by a game launch hours
		// in) gets its own batched report instead of being lost.
		if (g_scheduled.exchange(true, std::memory_order_acq_rel))
			return;

		std::thread([]
		{
			std::this_thread::sleep_for(std::chrono::seconds(20));

			std::vector<Entry> snap;
			{
				std::lock_guard<std::mutex> lk(g_mtx);
				snap = std::move(g_entries);
				g_entries.clear();
			}
			g_scheduled.store(false, std::memory_order_release);

			if (!snap.empty())
				emit(std::move(snap));
		}).detach();
	}

	void emit(std::vector<Entry>&& batch)
	{
		if (!g_pLog)
			return;

		size_t vftStatic = 0, vftDynamic = 0, patReq = 0, patOpt = 0;
		for (const auto& e : batch)
		{
			switch (e.kind)
			{
				case Kind::VFTStatic:      ++vftStatic;  break;
				case Kind::VFTDynamic:     ++vftDynamic; break;
				case Kind::PatternMissing: (e.optional ? ++patOpt : ++patReq); break;
			}
		}

		std::stringstream ss;
		ss << "steamclient drift detected — " << batch.size() << " issue(s):\n";

		if (vftStatic + vftDynamic > 0)
		{
			ss << "  VFThook drift (" << (vftStatic + vftDynamic)
			   << "): wrong vtable slot, hook skipped or removed.\n";
			for (const auto& e : batch)
			{
				if (e.kind == Kind::VFTStatic)
				{
					ss << "    [vtable " << e.index << "] " << e.name
					   << "  -> pool says '" << e.actual << "' (static, skipped)\n";
				}
				else if (e.kind == Kind::VFTDynamic)
				{
					ss << "    [runtime]    " << e.name
					   << "  -> TraceIPC saw '" << e.actual << "' (removed)\n";
				}
			}
		}

		if (patReq + patOpt > 0)
		{
			ss << "  Pattern misses (" << patReq << " required, " << patOpt
			   << " optional): not located in .text or online.\n";
			for (const auto& e : batch)
				if (e.kind == Kind::PatternMissing)
					ss << "    " << (e.optional ? "[opt]" : "[REQ]") << " " << e.name << "\n";
		}

		ss << "Fix: update res/patterns.toml (vft_index for VFThook drift; pattern signatures for misses), rebuild or wait for OnlinePatterns fetch.";

		// Debug-level: developer-facing only, no notify-send popup. End users see no
		// drift noise; flip LogLevel to 1 (Debug) to surface during diagnosis.
		g_pLog->debug("%s\n", ss.str().c_str());
	}
}

void DriftReport::pushStaticVFTMismatch(const char* hookName, unsigned int index, const char* expected, const char* actualAtIndex)
{
	{
		std::lock_guard<std::mutex> lk(g_mtx);
		g_entries.push_back({
			Kind::VFTStatic,
			hookName ? hookName : "",
			index,
			expected ? expected : "",
			actualAtIndex ? actualAtIndex : "",
			false
		});
	}
	schedule();
}

void DriftReport::pushDynamicVFTMismatch(const char* hookName, const char* expected, const char* actualIface, const char* actualFn)
{
	std::string combined;
	if (actualIface) combined.append(actualIface);
	combined.append("::");
	if (actualFn) combined.append(actualFn);

	{
		std::lock_guard<std::mutex> lk(g_mtx);
		g_entries.push_back({
			Kind::VFTDynamic,
			hookName ? hookName : "",
			0,
			expected ? expected : "",
			std::move(combined),
			false
		});
	}
	schedule();
}

void DriftReport::pushUnresolvedPattern(const char* patternName, bool optional)
{
	{
		std::lock_guard<std::mutex> lk(g_mtx);
		g_entries.push_back({
			Kind::PatternMissing,
			patternName ? patternName : "",
			0,
			"",
			"",
			optional
		});
	}
	schedule();
}
