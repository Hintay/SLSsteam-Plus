#include "protoninject.hpp"
#include "protoninject_protocol.h"

#include "../config.hpp"
#include "../globals.hpp"
#include "../log.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <filesystem>
#include <link.h>
#include <mutex>
#include <pthread.h>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unordered_map>
#include <unistd.h>
#include <vector>

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
	// We match by AppId (from envp) or by Flag (substring in argv), then
	// inject LD_PRELOAD + ProtonInject protocol env vars into envp.

	using execvpe_fn = int(*)(const char*, char* const[], char* const[]);
	execvpe_fn g_origExecvpe = nullptr;

	struct InjectEntry {
		std::string dllPath;
		std::string sessionToken;
	};
	struct FlagEntry {
		std::string flag;
		InjectEntry inject;
	};
	struct LaunchRules {
		uint32_t appId = 0;
		std::string helperSo;
		std::unordered_map<uint32_t, InjectEntry> dllByApp;
		std::vector<FlagEntry> dllByFlag;
	};

	std::mutex g_launchRulesMu;
	std::unordered_map<uint32_t, LaunchRules> g_launchRulesByApp;

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

	uint32_t getLaunchAppId(char* const envp[])
	{
		return sls_proton_select_app_id(
			nullptr,
			getEnvValue(envp, "SteamAppId"),
			getEnvValue(envp, "SteamGameId"));
	}

	void clearLaunchRules()
	{
		std::lock_guard<std::mutex> lock(g_launchRulesMu);
		g_launchRulesByApp.clear();
	}

	void eraseLaunchRules(uint32_t appId)
	{
		std::lock_guard<std::mutex> lock(g_launchRulesMu);
		g_launchRulesByApp.erase(appId);
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

	struct LaunchMatch {
		uint32_t appId = 0;
		std::string helperSo;
		std::string dllPath;
		std::string sessionToken;
		int argIndex = -1;
		size_t flagPos = 0;
		size_t flagLen = 0;
	};

	struct PendingSession {
		uint32_t appId = 0;
		std::string dllPath;
	};

	std::mutex g_pendingSessionsMu;
	std::unordered_map<std::string, PendingSession> g_pendingSessions;
	int g_controlFd = -1;
	pthread_t g_controlThread{};
	bool g_controlThreadStarted = false;

	bool buildAbstractSocketAddress(const char* token, sockaddr_un& addr, socklen_t& len)
	{
		char socketName[sizeof(addr.sun_path) - 1] = {};
		if (!sls_proton_build_socket_name(socketName, sizeof(socketName), token)) return false;
		const size_t nameLen = strlen(socketName);
		if (nameLen + 1 > sizeof(addr.sun_path)) return false;
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		addr.sun_path[0] = '\0';
		memcpy(addr.sun_path + 1, socketName, nameLen);
		len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + nameLen);
		return true;
	}

	bool writeAll(int fd, const char* data, size_t len)
	{
		while (len > 0) {
			ssize_t n = write(fd, data, len);
			if (n < 0) {
				if (errno == EINTR) continue;
				return false;
			}
			if (n == 0) return false;
			data += n;
			len -= static_cast<size_t>(n);
		}
		return true;
	}

	void handleControlClient(int clientFd)
	{
		char token[128] = {};
		ssize_t n = read(clientFd, token, sizeof(token) - 1);
		if (n <= 0) {
			close(clientFd);
			return;
		}
		token[n] = '\0';
		for (char* p = token; *p; ++p) {
			if (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t') {
				*p = '\0';
				break;
			}
		}

		PendingSession session;
		bool found = false;
		{
			// Tokens are single-use: once a Wine child has resolved its DLL
			// path the entry is no longer reachable, and replaying the same
			// token shouldn't leak the path to anyone else. Erase on consume.
			std::lock_guard<std::mutex> lock(g_pendingSessionsMu);
			auto it = g_pendingSessions.find(token);
			if (it != g_pendingSessions.end()) {
				session = std::move(it->second);
				g_pendingSessions.erase(it);
				found = true;
			}
		}

		char response[1024] = {};
		if (found && sls_proton_build_ok_response(response, sizeof(response), session.appId, session.dllPath.c_str())) {
			if (!writeAll(clientFd, response, strlen(response)))
				g_pLog->warn("ProtonInject: failed to write IPC response\n");
		} else {
			static const char deny[] = SLS_PROTON_INJECT_PROTO_MAGIC " DENY unknown-session\n";
			if (!writeAll(clientFd, deny, sizeof(deny) - 1))
				g_pLog->warn("ProtonInject: failed to write IPC deny response\n");
		}
		close(clientFd);
	}

	void* controlThreadMain(void*)
	{
		for (;;) {
			int clientFd = accept(g_controlFd, nullptr, nullptr);
			if (clientFd < 0) {
				if (errno == EINTR) continue;
				break;
			}
			handleControlClient(clientFd);
		}
		return nullptr;
	}

	bool ensureControlServer()
	{
		if (g_controlThreadStarted) return true;

		int fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd < 0) {
			g_pLog->warn("ProtonInject: failed to create control socket\n");
			return false;
		}

		sockaddr_un addr{};
		socklen_t len = 0;
		if (!buildAbstractSocketAddress(SLS_PROTON_INJECT_CONTROL_TOKEN, addr, len) ||
		    bind(fd, reinterpret_cast<sockaddr*>(&addr), len) != 0 ||
		    listen(fd, 16) != 0) {
			g_pLog->warn("ProtonInject: failed to bind control socket\n");
			close(fd);
			return false;
		}

		g_controlFd = fd;
		if (pthread_create(&g_controlThread, nullptr, controlThreadMain, nullptr) != 0) {
			g_pLog->warn("ProtonInject: failed to start control thread\n");
			close(fd);
			g_controlFd = -1;
			return false;
		}
		pthread_detach(g_controlThread);
		g_controlThreadStarted = true;
		return true;
	}

	std::string registerPendingSession(uint32_t appId, const std::string& dllPath)
	{
		// Sequence counter is incremented atomically — execvpe is hooked at the
		// GOT slot and may be called from any Steam thread (fork() helpers are
		// not guaranteed to be on the main thread), so this could race with
		// concurrent LaunchApp callbacks.
		static std::atomic<uint64_t> seq{0};
		timespec ts{};
		clock_gettime(CLOCK_MONOTONIC, &ts);
		const uint64_t seqValue = seq.fetch_add(1, std::memory_order_relaxed) + 1;
		char token[96] = {};
		snprintf(token, sizeof(token), "%u-%ld-%ld-%llu", appId, static_cast<long>(ts.tv_sec),
		         static_cast<long>(ts.tv_nsec), static_cast<unsigned long long>(seqValue));

		std::lock_guard<std::mutex> lock(g_pendingSessionsMu);
		g_pendingSessions[token] = {appId, dllPath};
		return token;
	}

	// Drop any pending session tokens belonging to `appId`. Called from
	// onLaunchApp so a re-launch (or a launch that never produced a Wine
	// child) does not accumulate unclaimed tokens.
	void dropPendingSessionsForApp(uint32_t appId)
	{
		std::lock_guard<std::mutex> lock(g_pendingSessionsMu);
		for (auto it = g_pendingSessions.begin(); it != g_pendingSessions.end(); ) {
			if (it->second.appId == appId)
				it = g_pendingSessions.erase(it);
			else
				++it;
		}
	}

	LaunchMatch findFlagMatch(const LaunchRules& rules, char* const argv[])
	{
		if (rules.dllByFlag.empty() || !argv) return {};
		for (int i = 0; argv[i]; i++) {
			for (const auto& fe : rules.dllByFlag) {
				const char* pos = strstr(argv[i], fe.flag.c_str());
				if (!pos) continue;
				size_t off = pos - argv[i];
				size_t flen = fe.flag.size();
				char after = pos[flen];
				char before = (off > 0) ? pos[-1] : ' '; /* start-of-string counts as boundary */
				if ((before == ' ' || before == '\t') &&
				    (after == '\0' || after == ' ' || after == '\t' || after == '\''))
					return {rules.appId, rules.helperSo, fe.inject.dllPath, fe.inject.sessionToken, i, off, flen};
			}
		}
		return {};
	}

	LaunchMatch findDllForLaunch(char* const argv[], char* const envp[])
	{
		const uint32_t appId = getLaunchAppId(envp);
		std::lock_guard<std::mutex> lock(g_launchRulesMu);

		if (appId) {
			auto rulesIt = g_launchRulesByApp.find(appId);
			if (rulesIt != g_launchRulesByApp.end()) {
				auto appIt = rulesIt->second.dllByApp.find(appId);
				if (appIt != rulesIt->second.dllByApp.end())
					return {appId, rulesIt->second.helperSo, appIt->second.dllPath, appIt->second.sessionToken, -1, 0, 0};

				LaunchMatch byFlag = findFlagMatch(rulesIt->second, argv);
				if (!byFlag.dllPath.empty()) return byFlag;
			}

			return {};
		}

		// If Steam's envp did not expose an AppId, fall back to launch-option flags.
		for (const auto& [_, rules] : g_launchRulesByApp) {
			LaunchMatch byFlag = findFlagMatch(rules, argv);
			if (!byFlag.dllPath.empty()) return byFlag;
		}

		return {};
	}

	LaunchRules buildLaunchRules(const CConfig::ProtonInjectConfig& cfg, uint32_t currentAppId, const std::string& helperSo)
	{
		LaunchRules rules;
		rules.appId = currentAppId;
		rules.helperSo = helperSo;
		for (const auto& entry : cfg.dlls) {
			if (entry.path.empty()) continue;
			const bool relevant = entry.apps.count(currentAppId) || !entry.flag.empty();
			if (!std::filesystem::exists(entry.path)) {
				if (relevant)
					g_pLog->warn("ProtonInject: DLL not found: %s\n", entry.path.c_str());
				continue;
			}
			if (entry.apps.count(currentAppId))
				rules.dllByApp[currentAppId] = {entry.path, registerPendingSession(currentAppId, entry.path)};
			if (!entry.flag.empty())
				rules.dllByFlag.push_back({entry.flag, {entry.path, registerPendingSession(currentAppId, entry.path)}});
		}
		return rules;
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

		const auto match = findDllForLaunch(argv, envp);
		if (match.dllPath.empty() || match.helperSo.empty() || !match.appId)
			return g_origExecvpe(file, argv, envp);

		/* If matched by flag, strip it from the argv string so the game
		 * doesn't see it. Steam passes the whole command as /bin/sh -c "...",
		 * so the flag is a substring within argv[2], not a separate element. */
		char** newArgv = const_cast<char**>(argv);
		std::string patchedArg;
		if (match.argIndex >= 0) {
			patchedArg = argv[match.argIndex];
			patchedArg.erase(match.flagPos, match.flagLen);
			/* Collapse double spaces left by removal */
			while (match.flagPos < patchedArg.size() && match.flagPos > 0 &&
			       patchedArg[match.flagPos] == ' ' && patchedArg[match.flagPos - 1] == ' ')
				patchedArg.erase(match.flagPos, 1);

			int argc = 0;
			while (argv[argc]) argc++;
			newArgv = static_cast<char**>(alloca((argc + 1) * sizeof(char*)));
			for (int i = 0; i < argc; i++)
				newArgv[i] = (i == match.argIndex) ? const_cast<char*>(patchedArg.c_str()) : argv[i];
			newArgv[argc] = nullptr;
		}

		// Count envp entries
		int count = 0;
		while (envp[count]) count++;

		if (match.sessionToken.empty())
			return g_origExecvpe(file, argv, envp);

		std::string sessionEntry = std::string(SLS_PROTON_INJECT_SESSION_ENV) + "=" + match.sessionToken;

		// Build new envp: append helper preload and opaque IPC session token.
		// +2 for LD_PRELOAD + session, +1 for NULL
		char** newEnvp = static_cast<char**>(alloca((count + 3) * sizeof(char*)));

		std::string ldPreloadEntry;
		for (int i = 0; i < count; i++) {
			if (startsWith(envp[i], "LD_PRELOAD=")) {
				const char* curPreload = envp[i] + 11;
				if (colonListContains(curPreload, match.helperSo))
					ldPreloadEntry = envp[i];
				else
					ldPreloadEntry = std::string(envp[i]) + ":" + match.helperSo;
				break;
			}
		}
		if (ldPreloadEntry.empty())
			ldPreloadEntry = "LD_PRELOAD=" + match.helperSo;

		int dst = 0;
		bool replacedPreload = false;
		bool replacedSession = false;
		for (int i = 0; i < count; i++) {
			if (startsWith(envp[i], "LD_PRELOAD=")) {
				newEnvp[dst++] = const_cast<char*>(ldPreloadEntry.c_str());
				replacedPreload = true;
			} else if (startsWith(envp[i], SLS_PROTON_INJECT_SESSION_ENV "=")) {
				newEnvp[dst++] = const_cast<char*>(sessionEntry.c_str());
				replacedSession = true;
			} else {
				newEnvp[dst++] = envp[i];
			}
		}
		if (!replacedPreload)
			newEnvp[dst++] = const_cast<char*>(ldPreloadEntry.c_str());
		if (!replacedSession)
			newEnvp[dst++] = const_cast<char*>(sessionEntry.c_str());
		newEnvp[dst] = nullptr;

		return g_origExecvpe(file, newArgv, newEnvp);
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
	// Drop any tokens left behind by a previous launch of this app
	// (game crashed before its Wine helper connected, user cancelled, etc.)
	// so g_pendingSessions stays bounded across re-launches.
	dropPendingSessionsForApp(appId);

	const auto cfg = g_config.protonInject.get();
	if (cfg.dlls.empty()) {
		clearLaunchRules();
		return;
	}

	const std::string helperSo = findHelperSo("sls_proton_inject.so", cfg.dir);
	if (helperSo.empty()) {
		clearLaunchRules();
		g_pLog->warn("ProtonInject: sls_proton_inject.so not found\n");
		return;
	}

	if (!ensureControlServer()) {
		clearLaunchRules();
		return;
	}

	LaunchRules rules = buildLaunchRules(cfg, appId, helperSo);
	if (rules.dllByApp.empty() && rules.dllByFlag.empty()) {
		eraseLaunchRules(appId);
		return;
	}

	if (!g_hooked) {
		g_hooked = installHooks();
		if (!g_hooked) {
			eraseLaunchRules(appId);
			return;
		}
	}

	{
		std::lock_guard<std::mutex> lock(g_launchRulesMu);
		g_launchRulesByApp[appId] = rules;
	}

	auto appIt = rules.dllByApp.find(appId);
	if (appIt != rules.dllByApp.end())
		g_pLog->info("ProtonInject: appId %u -> %s\n", appId, appIt->second.dllPath.c_str());
	else if (!rules.dllByFlag.empty())
		g_pLog->info("ProtonInject: appId %u (flag matching active, %zu rules)\n", appId, rules.dllByFlag.size());
}
