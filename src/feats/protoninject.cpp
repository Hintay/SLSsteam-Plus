#include "protoninject.hpp"

#include "../config.hpp"
#include "../globals.hpp"
#include "../log.hpp"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <filesystem>
#include <link.h>
#include <string>
#include <sys/mman.h>
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

	std::atomic<bool> g_injectPending{false};
	std::string g_injectLdAudit;
	std::string g_injectDllMapping;

	int hooked_execvpe(const char* file, char* const argv[], char* const envp[])
	{
		if (!g_injectPending.load() || !envp) {
			return g_origExecvpe(file, argv, envp);
		}

		// Count envp entries
		int count = 0;
		while (envp[count]) count++;

		// Build new envp: append inject .so to LD_PRELOAD (NOT LD_AUDIT —
		// glibc treats LD_AUDIT libs differently: no constructor execution).
		// +2 for LD_PRELOAD + PROTON_SLS_INJECT_DLL, +1 for NULL
		char** newEnvp = static_cast<char**>(alloca((count + 3) * sizeof(char*)));

		std::string dllEntry = "PROTON_SLS_INJECT_DLL=" + g_injectDllMapping;

		// Also append to LD_PRELOAD so Wine (which ignores LD_AUDIT) loads it.
		// Extract inject .so paths from g_injectLdAudit (contains full LD_AUDIT value).
		// g_injectLdAudit looks like: ".../libSLSsteam-test.so:.../sls_proton_inject.so:.../sls_proton_inject32.so"
		// We need to extract paths containing "sls_proton_inject".
		std::string injectSoPaths;
		{
			std::string src = g_injectLdAudit;
			size_t pos = 0;
			while (pos < src.size()) {
				size_t sep = src.find(':', pos);
				std::string entry = (sep != std::string::npos) ? src.substr(pos, sep - pos) : src.substr(pos);
				if (entry.find("sls_proton_inject") != std::string::npos) {
					if (!injectSoPaths.empty()) injectSoPaths += ':';
					injectSoPaths += entry;
				}
				pos = (sep != std::string::npos) ? sep + 1 : src.size();
			}
		}

		std::string ldPreloadEntry;
		if (!injectSoPaths.empty()) {
			for (int i = 0; i < count; i++) {
				if (strncmp(envp[i], "LD_PRELOAD=", 11) == 0) {
					ldPreloadEntry = std::string(envp[i]) + ":" + injectSoPaths;
					break;
				}
			}
			if (ldPreloadEntry.empty())
				ldPreloadEntry = "LD_PRELOAD=" + injectSoPaths;
		}

		int dst = 0;
		bool replacedPreload = false;
		for (int i = 0; i < count; i++) {
			if (!ldPreloadEntry.empty() && strncmp(envp[i], "LD_PRELOAD=", 11) == 0) {
				newEnvp[dst++] = const_cast<char*>(ldPreloadEntry.c_str());
				replacedPreload = true;
			} else {
				newEnvp[dst++] = envp[i];
			}
		}
		if (!replacedPreload && !ldPreloadEntry.empty())
			newEnvp[dst++] = const_cast<char*>(ldPreloadEntry.c_str());
		newEnvp[dst++] = const_cast<char*>(dllEntry.c_str());
		newEnvp[dst] = nullptr;

		g_injectPending.store(false);
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
		auto page = reinterpret_cast<uintptr_t>(execvpeSlot) & ~0xFFFUL;
		mprotect(reinterpret_cast<void*>(page), 0x1000, PROT_READ | PROT_WRITE);
		*execvpeSlot = reinterpret_cast<void*>(hooked_execvpe);

		g_pLog->info("ProtonInject: execvpe GOT hooked at %p\n", execvpeSlot);
		return true;
	}
}

void ProtonInject::onLaunchApp(uint32_t appId)
{
	const auto cfg = g_config.protonInject.get();
	if (cfg.dlls.empty()) return;

	std::string dllPath;
	for (const auto& entry : cfg.dlls) {
		if (entry.apps.count(appId) && !entry.path.empty()) {
			if (std::filesystem::exists(entry.path)) {
				dllPath = entry.path;
				break;
			}
			g_pLog->warn("ProtonInject: DLL not found: %s\n", entry.path.c_str());
		}
	}
	if (dllPath.empty()) return;

	const std::string so64 = findHelperSo("sls_proton_inject.so", cfg.dir);
	const std::string so32 = findHelperSo("sls_proton_inject32.so", cfg.dir);
	if (so64.empty() && so32.empty()) {
		g_pLog->warn("ProtonInject: no sls_proton_inject*.so found\n");
		return;
	}

	if (!g_hooked) {
		g_hooked = installHooks();
		if (!g_hooked) return;
	}

	// Build LD_AUDIT with inject .so appended
	const char* curAudit = std::getenv("LD_AUDIT");
	std::string newAudit = curAudit ? curAudit : "";
	if (newAudit.find("sls_proton_inject") == std::string::npos) {
		if (!newAudit.empty()) newAudit += ':';
		if (!so64.empty()) newAudit += so64;
		if (!so32.empty()) {
			if (!so64.empty()) newAudit += ':';
			newAudit += so32;
		}
	}

	g_injectLdAudit = newAudit;
	g_injectDllMapping = dllPath;
	g_injectPending.store(true);

	g_pLog->info("ProtonInject: appId %u -> %s (pending exec)\n", appId, dllPath.c_str());
}
