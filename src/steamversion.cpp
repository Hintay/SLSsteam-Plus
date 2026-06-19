#include "steamversion.hpp"

#include "log.hpp"

#include <dlfcn.h>
#include <mutex>

namespace
{
	uint32_t g_cached = 0;
	std::once_flag g_once;
}

uint32_t SteamVersion::get()
{
	std::call_once(g_once, []
	{
		using Fn = uint32_t(*)();
		void* tier0 = dlopen("libtier0_s.so", RTLD_NOLOAD | RTLD_NOW);
		if (tier0)
		{
			auto fn = reinterpret_cast<Fn>(dlsym(tier0, "GetMiniDumpBuildID"));
			if (fn)
				g_cached = fn();
		}
		if (!g_cached)
			g_pLog->debug("SteamVersion: GetMiniDumpBuildID unavailable or returned 0\n");
	});

	return g_cached;
}
