#include "protoninject.hpp"

#include "../config.hpp"
#include "../globals.hpp"
#include "../log.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <filesystem>
#include <link.h>
#include <string>
#include <sys/mman.h>
#include <unordered_map>
#include <unistd.h>

namespace
{
	std::string getOwnDir()
	{
		static std::string cached;
		if (!cached.empty()) return cached;
		Dl_info info{};
		if (dladdr(reinterpret_cast<void*>(&getOwnDir), &info) && info.dli_fname)
			cached = std::filesystem::path(info.dli_fname).parent_path().string();
		return cached;
	}

	std::string findHelperSo(const char* name, const std::string& cfgDir)
	{
		const auto& ownDir = getOwnDir();
		if (!ownDir.empty()) {
			auto c = std::filesystem::path(ownDir) / name;
			if (std::filesystem::exists(c)) return c.string();
		}
		if (!cfgDir.empty()) {
			auto c = std::filesystem::path(cfgDir) / name;
			if (std::filesystem::exists(c)) return c.string();
		}
		return "";
	}

	// ── ELF GOT slot lookup ────────────────────────────────────────
	void** findGotSlot(const char* symName)
	{
		auto base = reinterpret_cast<uintptr_t>(g_modSteamClient.base);
		auto* ehdr = reinterpret_cast<Elf32_Ehdr*>(base);
		auto* phdr = reinterpret_cast<Elf32_Phdr*>(base + ehdr->e_phoff);

		Elf32_Dyn* dyn = nullptr;
		for (int i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_type == PT_DYNAMIC) {
				dyn = reinterpret_cast<Elf32_Dyn*>(base + phdr[i].p_vaddr);
				break;
			}
		}
		if (!dyn) return nullptr;

		Elf32_Rel* jmprel = nullptr;
		uint32_t jmprelsz = 0;
		Elf32_Sym* symtab = nullptr;
		const char* strtab = nullptr;

		bool relocated = false;
		for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
			if (dyn[i].d_tag == DT_STRTAB) {
				relocated = (dyn[i].d_un.d_ptr >= base);
				break;
			}
		}
		for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
			uintptr_t ptr = relocated ? dyn[i].d_un.d_ptr : (base + dyn[i].d_un.d_ptr);
			switch (dyn[i].d_tag) {
				case DT_JMPREL:   jmprel   = reinterpret_cast<Elf32_Rel*>(ptr); break;
				case DT_PLTRELSZ: jmprelsz = dyn[i].d_un.d_val; break;
				case DT_SYMTAB:   symtab   = reinterpret_cast<Elf32_Sym*>(ptr); break;
				case DT_STRTAB:   strtab   = reinterpret_cast<const char*>(ptr); break;
			}
		}
		if (!jmprel || !symtab || !strtab || !jmprelsz) return nullptr;

		uint32_t nrel = jmprelsz / sizeof(Elf32_Rel);
		for (uint32_t i = 0; i < nrel; i++) {
			uint32_t sym_idx = ELF32_R_SYM(jmprel[i].r_info);
			const char* name = strtab + symtab[sym_idx].st_name;
			if (strcmp(name, symName) == 0) {
				uintptr_t got_addr = (jmprel[i].r_offset >= base)
					? jmprel[i].r_offset : (base + jmprel[i].r_offset);
				return reinterpret_cast<void**>(got_addr);
			}
		}
		return nullptr;
	}

	// ── execvpe GOT hook ───────────────────────────────────────────
	// Steam calls execvpe(file, argv, envp) in the child after fork.
	// envp is CProcessEnvironmentManager's array — we append our vars to it.

	using execvpe_fn = int(*)(const char*, char* const[], char* const[]);
	execvpe_fn g_origExecvpe = nullptr;

	std::string g_injectPreloadPaths;
	std::unordered_map<uint32_t, std::string> g_injectDllByApp;

	size_t getSystemPageSize()
	{
		long pageSize = sysconf(_SC_PAGESIZE);
		return pageSize > 0 ? static_cast<size_t>(pageSize) : 4096;
	}

	uintptr_t alignPageDown(uintptr_t address, size_t pageSize)
	{
		return address & ~(static_cast<uintptr_t>(pageSize) - 1);
	}

	bool startsWith(const char* value, const char* prefix)
	{
		return strncmp(value, prefix, strlen(prefix)) == 0;
	}

	const char* getEnvValue(char* const envp[], const char* name)
	{
		const size_t nameLen = strlen(name);
		for (int i = 0; envp && envp[i]; i++) {
			if (strncmp(envp[i], name, nameLen) == 0 && envp[i][nameLen] == '=')
				return envp[i] + nameLen + 1;
		}
		return nullptr;
	}

	bool parseAppId(const char* value, uint32_t& appId)
	{
		if (!value || !*value) return false;
		for (const char* p = value; *p; p++) {
			if (*p < '0' || *p > '9') return false;
		}
		char* end = nullptr;
		unsigned long parsed = strtoul(value, &end, 10);
		if (!end || *end != '\0' || parsed > UINT32_MAX) return false;
		appId = static_cast<uint32_t>(parsed);
		return true;
	}

	void clearInjectRules()
	{
		g_injectPreloadPaths.clear();
		g_injectDllByApp.clear();
	}

	bool colonListContains(const char* value, const std::string& needle)
	{
		if (!value || needle.empty()) return false;
		const char* pos = value;
		while (*pos) {
			const char* sep = strchr(pos, ':');
			const size_t len = sep ? static_cast<size_t>(sep - pos) : strlen(pos);
			if (needle.size() == len && strncmp(pos, needle.c_str(), len) == 0)
				return true;
			if (!sep) break;
			pos = sep + 1;
		}
		return false;
	}

	std::string findDllForEnv(char* const envp[])
	{
		uint32_t appId = 0;
		if (!parseAppId(getEnvValue(envp, "SteamAppId"), appId))
			parseAppId(getEnvValue(envp, "SteamGameId"), appId);
		if (!appId) return "";

		auto it = g_injectDllByApp.find(appId);
		return it != g_injectDllByApp.end() ? it->second : "";
	}

	void refreshInjectRules(const CConfig::ProtonInjectConfig& cfg, uint32_t currentAppId)
	{
		g_injectDllByApp.clear();
		for (const auto& entry : cfg.dlls) {
			if (entry.path.empty()) continue;
			if (!std::filesystem::exists(entry.path)) {
				if (entry.apps.count(currentAppId))
					g_pLog->warn("ProtonInject: DLL not found: %s\n", entry.path.c_str());
				continue;
			}
			for (const auto appId : entry.apps)
				g_injectDllByApp.emplace(appId, entry.path);
		}
	}

	int getPageProtection(uintptr_t address)
	{
		FILE* maps = fopen("/proc/self/maps", "r");
		if (!maps) return PROT_READ;

		char line[512];
		while (fgets(line, sizeof(line), maps)) {
			unsigned long start = 0;
			unsigned long end = 0;
			char perms[5] = {};
			if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3 &&
			    address >= start && address < end) {
				int prot = 0;
				if (perms[0] == 'r') prot |= PROT_READ;
				if (perms[1] == 'w') prot |= PROT_WRITE;
				if (perms[2] == 'x') prot |= PROT_EXEC;
				fclose(maps);
				return prot ? prot : PROT_READ;
			}
		}

		fclose(maps);
		return PROT_READ;
	}

	int hooked_execvpe(const char* file, char* const argv[], char* const envp[])
	{
		if (!envp) {
			return g_origExecvpe(file, argv, envp);
		}

		const std::string dllPath = findDllForEnv(envp);
		if (dllPath.empty() || g_injectPreloadPaths.empty())
			return g_origExecvpe(file, argv, envp);

		// Count envp entries
		int count = 0;
		while (envp[count]) count++;

		// Build new envp: append the 64-bit helper to LD_PRELOAD so Wine loads it.
		// +2 for LD_PRELOAD + PROTON_SLS_INJECT_DLL, +1 for NULL
		char** newEnvp = static_cast<char**>(alloca((count + 3) * sizeof(char*)));

		std::string dllEntry = "PROTON_SLS_INJECT_DLL=" + dllPath;

		std::string ldPreloadEntry;
		for (int i = 0; i < count; i++) {
			if (startsWith(envp[i], "LD_PRELOAD=")) {
				const char* curPreload = envp[i] + 11;
				if (colonListContains(curPreload, g_injectPreloadPaths))
					ldPreloadEntry = envp[i];
				else
					ldPreloadEntry = std::string(envp[i]) + ":" + g_injectPreloadPaths;
				break;
			}
		}
		if (ldPreloadEntry.empty())
			ldPreloadEntry = "LD_PRELOAD=" + g_injectPreloadPaths;

		int dst = 0;
		bool replacedPreload = false;
		bool replacedDll = false;
		for (int i = 0; i < count; i++) {
			if (startsWith(envp[i], "LD_PRELOAD=")) {
				newEnvp[dst++] = const_cast<char*>(ldPreloadEntry.c_str());
				replacedPreload = true;
			} else if (startsWith(envp[i], "PROTON_SLS_INJECT_DLL=")) {
				newEnvp[dst++] = const_cast<char*>(dllEntry.c_str());
				replacedDll = true;
			} else {
				newEnvp[dst++] = envp[i];
			}
		}
		if (!replacedPreload)
			newEnvp[dst++] = const_cast<char*>(ldPreloadEntry.c_str());
		if (!replacedDll)
			newEnvp[dst++] = const_cast<char*>(dllEntry.c_str());
		newEnvp[dst] = nullptr;

		return g_origExecvpe(file, argv, newEnvp);
	}

	bool g_hooked = false;

	bool installHooks()
	{
		// Hook execvpe GOT
		void** execvpeSlot = findGotSlot("execvpe");
		if (!execvpeSlot) {
			g_pLog->warn("ProtonInject: execvpe GOT slot not found\n");
			return false;
		}

		g_origExecvpe = reinterpret_cast<execvpe_fn>(*execvpeSlot);
		const size_t pageSize = getSystemPageSize();
		auto page = alignPageDown(reinterpret_cast<uintptr_t>(execvpeSlot), pageSize);
		const int originalProt = getPageProtection(page);
		if (mprotect(reinterpret_cast<void*>(page), pageSize, originalProt | PROT_WRITE) != 0) {
			g_pLog->warn("ProtonInject: failed to make execvpe GOT writable\n");
			return false;
		}
		*execvpeSlot = reinterpret_cast<void*>(hooked_execvpe);
		if (mprotect(reinterpret_cast<void*>(page), pageSize, originalProt) != 0)
			g_pLog->warn("ProtonInject: failed to restore execvpe GOT protection\n");

		g_pLog->info("ProtonInject: execvpe GOT hooked at %p\n", execvpeSlot);
		return true;
	}
}

void ProtonInject::onLaunchApp(uint32_t appId)
{
	const auto cfg = g_config.protonInject.get();
	if (cfg.dlls.empty()) {
		clearInjectRules();
		return;
	}

	const std::string helperSo = findHelperSo("sls_proton_inject.so", cfg.dir);
	if (helperSo.empty()) {
		clearInjectRules();
		g_pLog->warn("ProtonInject: sls_proton_inject.so not found\n");
		return;
	}

	refreshInjectRules(cfg, appId);
	if (!g_injectDllByApp.count(appId)) return;
	g_injectPreloadPaths = helperSo;

	if (!g_hooked) {
		g_hooked = installHooks();
		if (!g_hooked) return;
	}

	g_pLog->info("ProtonInject: appId %u -> %s\n", appId, g_injectDllByApp[appId].c_str());
}
