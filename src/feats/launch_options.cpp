#include "launch_options.hpp"

#include "package.hpp"

#include "../globals.hpp"
#include "../log.hpp"
#include "../patterns.hpp"
#include "../sdk/CSteamEngine.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>

namespace
{
	// Query the user's "Set Launch Options..." string for an app via the
	// per-user CConfigStore subobject embedded inside CUser at a
	// version-dependent offset resolved at runtime from the
	// CUser::Offset_ConfigStore pattern (see patterns.toml).
	//
	// localconfig.vdf stores this at
	//   Software\Valve\Steam\Apps\<appid>\LaunchOptions
	// inside store enum 3 (UserLocalConfigStore).
	//
	// Reverse-engineered from steamclient.so internal launch-app helper:
	//   ctx = function arg                          ; CUserAppInfo*
	//   pCUser     = *(void**)(ctx + 0x80)          ; per-user object
	//   configThis = pCUser + <imm>                 ; embedded subobject (no deref)
	//   vft        = *(void***)configThis
	//   fn         = vft[5]                         ; offset 0x14
	//   value      = fn(configThis, 3, key, "")     ; returns const char*
	//
	// The CUser* anchor is the same instance captured by
	// hkUser_CheckAppOwnership into Package::setCUser.
	using InternalConfigStoreGetString_t =
		const char* (*)(void* this_, int store, const char* key, const char* defaultValue);

	bool isSteamClientAddress(uintptr_t address)
	{
		const auto base = reinterpret_cast<uintptr_t>(g_modSteamClient.base);
		return address >= base && address < base + g_modSteamClient.size;
	}

	uint32_t readUnalignedU32(lm_address_t address)
	{
		uint32_t value = 0;
		memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value));
		return value;
	}

	void* resolveCUser()
	{
		void* pCUser = Package::getCUser();
		if (pCUser) return pCUser;

		if (!g_pSteamEngine) return nullptr;

		pCUser = g_pSteamEngine->getUser(0);
		if (pCUser) {
			Package::setCUser(pCUser);
			g_pLog->debug("LaunchOptions: resolved CUser via CSteamEngine::getUser(0)\n");
		}
		return pCUser;
	}

	// Decode the imm32 offset from the matched CUser::Offset_ConfigStore byte
	// sequence and sanity-check it. Returns 0 (with a warn) on any failure
	// path so the caller can fall back to disabled launch-flag matching.
	//
	// The pattern brackets two redundant imm32 sites inside the launch-app
	// helper's CConfigStore::GetConfigString callsite:
	//
	//   8B 80 80 00 00 00   ; mov eax, [eax+0x80]    (pCUser = *(ctx+0x80))
	//   8D B0 ?? ?? ?? ??   ; lea esi, [eax+imm32]   ← imm32 #1 at base+0x08
	//   8B 80 ?? ?? ?? ??   ; mov eax, [eax+imm32]   ← imm32 #2 at base+0x0e
	//   8B 40 14            ; mov eax, [eax+0x14]    (vft[5])
	//
	// imm32 #1 and #2 must agree — they reference the same CConfigStore
	// subobject. Mismatch is the signal that the compiler folded the pattern
	// differently in a new Steam build and the offset needs re-RE'ing. Also
	// reject implausibly large values so a false-positive match doesn't drive
	// later vtable reads far outside the captured CUser object.
	//
	// Runs once via function-local static init at the first forApp() call.
	uintptr_t decodeConfigStoreOffset()
	{
		constexpr uint32_t kMaxReasonableConfigStoreOffset = 0x10000;
		const lm_address_t base = Patterns::CUser::Offset_ConfigStore.address;
		if (base == LM_ADDRESS_BAD) {
			g_pLog->warn("LaunchOptions: CUser::Offset_ConfigStore pattern not resolved — launch-flag matching disabled\n");
			return 0;
		}
		const uint32_t imm1 = readUnalignedU32(base + 0x08);
		const uint32_t imm2 = readUnalignedU32(base + 0x0e);
		if (imm1 != imm2) {
			g_pLog->warn("LaunchOptions: CUser::Offset_ConfigStore imm mismatch 0x%x != 0x%x — pattern drift suspected\n",
				imm1, imm2);
			return 0;
		}
		if (!imm1 || imm1 > kMaxReasonableConfigStoreOffset) {
			g_pLog->warn("LaunchOptions: CUser::Offset_ConfigStore decoded implausible offset 0x%x — pattern drift suspected\n",
				imm1);
			return 0;
		}
		g_pLog->debug("LaunchOptions: CUser+0x%x = CConfigStore (decoded from pattern @%p)\n",
			imm1, reinterpret_cast<void*>(base));
		return imm1;
	}
}

namespace LaunchOptions
{
	// Sole callers are LaunchApp hook handlers (Steam main thread). Static
	// caches are read/written only on that thread, so no synchronization.
	std::string forApp(uint32_t appId)
	{
		// Single-entry cache keyed on appId so back-to-back calls within the
		// same LaunchApp hook (FakeAppIds::onLaunchApp → LibraryInject::onLaunchApp)
		// hit cached value instead of round-tripping through the CConfigStore
		// vtable a second time. Same-thread invariants apply.
		static uint32_t s_cachedAppId = 0;
		static std::string s_cachedValue;
		static bool s_cachedValid = false;
		if (s_cachedValid && s_cachedAppId == appId) return s_cachedValue;

		static const uintptr_t offset = decodeConfigStoreOffset();
		if (!offset) return "";

		void* pCUser = resolveCUser();
		if (!pCUser) {
			g_pLog->debug("LaunchOptions: CUser not available — falling back to empty launch options\n");
			return "";
		}

		void* configThis = reinterpret_cast<char*>(pCUser) + offset;

		// Cache (configThis, fn). Re-resolve only if pCUser changes
		// (e.g. logout/login) — vtable[5] is otherwise stable for the
		// process lifetime.
		static void* s_configThis = nullptr;
		static InternalConfigStoreGetString_t s_fn = nullptr;
		if (s_configThis != configThis) {
			auto vft = *reinterpret_cast<void***>(configThis);
			void* fn = vft ? vft[5] : nullptr;
			if (fn && !isSteamClientAddress(reinterpret_cast<uintptr_t>(fn))) {
				g_pLog->warn("LaunchOptions: CConfigStore vft[5]=%p outside steamclient — launch-flag matching disabled\n",
					fn);
				fn = nullptr;
			}
			s_fn = reinterpret_cast<InternalConfigStoreGetString_t>(fn);
			s_configThis = configThis;
		}
		if (!s_fn) return "";

		char key[160];
		snprintf(key, sizeof(key),
			"Software\\Valve\\Steam\\Apps\\%u\\LaunchOptions", appId);

		const char* val = s_fn(configThis, 3, key, "");
		g_pLog->debug("LaunchOptions: CConfigStore::GetString(%u) -> \"%s\"\n",
			appId, val ? val : "(null)");
		s_cachedAppId = appId;
		s_cachedValue = val ? std::string(val) : "";
		s_cachedValid = true;
		return s_cachedValue;
	}

	// Word-boundary substring match: true if `needle` appears in `haystack`
	// with whitespace/start-of-string/quote on both sides.
	bool flagAppearsIn(const std::string& haystack, const std::string& needle)
	{
		if (needle.empty()) return false;
		size_t pos = 0;
		while ((pos = haystack.find(needle, pos)) != std::string::npos) {
			char before = (pos > 0) ? haystack[pos - 1] : ' ';
			size_t end = pos + needle.size();
			char after = (end < haystack.size()) ? haystack[end] : '\0';
			if ((before == ' ' || before == '\t' || before == '"' || before == '\'') &&
			    (after == '\0' || after == ' ' || after == '\t' || after == '"' || after == '\''))
				return true;
			pos = end;
		}
		return false;
	}
}
