#include "library_inject.hpp"
#include "protoninject_protocol.h"

#include "../config.hpp"
#include "../globals.hpp"
#include "../log.hpp"
#include "../sdk/IClientCompat.hpp"
#include "launch_options.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <cstdint>
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
#include <unordered_set>
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
		// FHS system locations. SLSsteam.so itself lives in /usr/lib32, but the
		// helper is 64-bit and packagers (e.g. Arch PKGBUILD) follow FHS by
		// installing it under /usr/lib (multilib-aware distros) or /usr/lib64
		// (older paths). Probe both so the .pkg install works out of the box.
		for (const char* dir : { "/usr/lib", "/usr/lib64" }) {
			auto c = std::filesystem::path(dir) / name;
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

	// One token per app session, registered in onLaunchApp (= Steam main
	// thread, pre-fork) so the child process running hooked_execvpe sees
	// the token via its fork copy of memory. Registering POST-fork inside
	// the child would write to the child's own g_pendingSessions, which
	// the control-socket server (parent) never sees — the helper would
	// always get DENY.
	// One installed record per AppId. The dispatcher pre-filters config entries
	// to a single platform per launch, so a record is either all-Proton or
	// all-native: `isNative` tags which, and helperSo/sessionToken carry the
	// Proton-only plumbing (empty for native records). byApp/byFlag hold the
	// library path keyed by AppId or by launch-flag respectively.
	struct LaunchRules {
		uint32_t appId = 0;
		bool isNative = false;
		std::string helperSo;     // Proton-only
		std::string sessionToken; // Proton-only; one per-session token, pre-fork
		std::unordered_map<uint32_t, std::string> byApp;            // appId -> lib path
		std::vector<std::pair<std::string, std::string>> byFlag;    // {flag, lib path}
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
		std::string helperSo;     // Proton-only; empty for native
		std::string libPath;      // Proton: user's DLL (passed to helper via token); native: .so to LD_PRELOAD
		std::string sessionToken; // Proton-only; empty for native
		bool isNative = false;
		int argIndex = -1;
		size_t flagPos = 0;
		size_t flagLen = 0;
	};

	struct PendingSession {
		uint32_t appId = 0;
		std::string dllPath;
		int64_t createdAtSec = 0; // CLOCK_MONOTONIC seconds at registration
	};

	// Stale-token TTL. A token must outlive Wine's full PE-process tree spawn
	// for the launch (services.exe / explorer.exe / the game itself); on a
	// cold Proton prefix that can take a couple of minutes. 10 minutes is well
	// past any realistic case while keeping g_pendingSessions bounded across
	// many distinct game launches in one Steam session.
	inline constexpr int64_t kPendingSessionTtlSec = 600;

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
		char buf[160] = {};
		ssize_t n = read(clientFd, buf, sizeof(buf) - 1);
		if (n <= 0) {
			close(clientFd);
			return;
		}
		buf[n] = '\0';
		// Strip trailing whitespace/newline.
		for (char* p = buf + strlen(buf); p > buf; --p) {
			const char c = *(p - 1);
			if (c == '\n' || c == '\r' || c == '\t' || c == ' ') *(p - 1) = '\0';
			else break;
		}

		// Token-only resolve request. Multi-use within the launch
		// (Wine spawns 20+ PE processes that all inherit the same token).
		// Drop is driven entirely by the GamesPlayed-diff observer plus
		// the TTL backstop, so this control socket has no client-initiated
		// drop verb.
		const char* token = buf;
		PendingSession session;
		bool found = false;
		{
			std::lock_guard<std::mutex> lock(g_pendingSessionsMu);
			auto it = g_pendingSessions.find(token);
			if (it != g_pendingSessions.end()) {
				session = it->second;
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
		static std::atomic<uint64_t> seq{0};
		timespec ts{};
		clock_gettime(CLOCK_MONOTONIC, &ts);
		const uint64_t seqValue = seq.fetch_add(1, std::memory_order_relaxed) + 1;
		char token[96] = {};
		snprintf(token, sizeof(token), "%u-%ld-%ld-%llu", appId, static_cast<long>(ts.tv_sec),
		         static_cast<long>(ts.tv_nsec), static_cast<unsigned long long>(seqValue));

		const int64_t nowSec = static_cast<int64_t>(ts.tv_sec);
		std::lock_guard<std::mutex> lock(g_pendingSessionsMu);
		for (auto it = g_pendingSessions.begin(); it != g_pendingSessions.end(); ) {
			if (nowSec - it->second.createdAtSec > kPendingSessionTtlSec)
				it = g_pendingSessions.erase(it);
			else
				++it;
		}
		g_pendingSessions[token] = {appId, dllPath, nowSec};
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

	// Whitespace/quote-bounded substring search of argv for any configured
	// launch-flag. Platform (helperSo/token/isNative) comes from the record.
	LaunchMatch findFlagMatch(const LaunchRules& rules, char* const argv[])
	{
		if (rules.byFlag.empty() || !argv) return {};
		for (int i = 0; argv[i]; i++) {
			for (const auto& [flag, libPath] : rules.byFlag) {
				const char* pos = strstr(argv[i], flag.c_str());
				if (!pos) continue;
				size_t off = pos - argv[i];
				size_t flen = flag.size();
				char after = pos[flen];
				char before = (off > 0) ? pos[-1] : ' '; /* start-of-string counts as boundary */
				if ((before == ' ' || before == '\t') &&
				    (after == '\0' || after == ' ' || after == '\t' || after == '\''))
					return {rules.appId, rules.helperSo, libPath, rules.sessionToken,
					        rules.isNative, i, off, flen};
			}
		}
		return {};
	}

	LaunchMatch findDllForLaunch(char* const argv[], char* const envp[])
	{
		const uint32_t appId = getLaunchAppId(envp);

		// This runs post-fork in the single-threaded child. fork() copies the
		// mutex in whatever state it had: if a parent thread held g_launchRulesMu
		// at fork time, the lock is frozen held by a thread that does not exist
		// here, so a blocking acquire would deadlock the child forever (game
		// never launches). try_lock instead: on the rare fork-during-write race
		// we fail to acquire and skip injection for this exec rather than hang.
		std::unique_lock<std::mutex> lock(g_launchRulesMu, std::try_to_lock);
		if (!lock.owns_lock())
			return {};

		if (appId) {
			auto rulesIt = g_launchRulesByApp.find(appId);
			if (rulesIt != g_launchRulesByApp.end()) {
				const auto& rules = rulesIt->second;

				auto appIt = rules.byApp.find(appId);
				if (appIt != rules.byApp.end())
					return {appId, rules.helperSo, appIt->second, rules.sessionToken,
					        rules.isNative, -1, 0, 0};

				LaunchMatch byFlag = findFlagMatch(rules, argv);
				if (!byFlag.libPath.empty()) return byFlag;
			}
			return {};
		}

		// AppId not in envp — fall back to launch-option flags across all known rule sets.
		for (const auto& [_, rules] : g_launchRulesByApp) {
			LaunchMatch byFlag = findFlagMatch(rules, argv);
			if (!byFlag.libPath.empty()) return byFlag;
		}

		return {};
	}

	// AppId rule first, then Flag against the user's LaunchOptions. Returns
	// nullptr with launchOpts unchanged when nothing matches; populates
	// launchOpts when the LaunchOptions string was queried.
	const CConfig::LibraryInjectEntry* pickEntry(
		const std::vector<CConfig::LibraryInjectEntry>& entries,
		uint32_t currentAppId,
		std::string& launchOpts)
	{
		for (const auto& entry : entries) {
			if (entry.path.empty()) continue;
			if (entry.apps.count(currentAppId) > 0) return &entry;
		}
		const bool hasFlagEntry = std::any_of(entries.begin(), entries.end(),
			[](const auto& e) { return !e.path.empty() && !e.flag.empty(); });
		if (!hasFlagEntry) return nullptr;
		launchOpts = LaunchOptions::forApp(currentAppId);
		for (const auto& entry : entries) {
			if (entry.path.empty() || entry.flag.empty()) continue;
			if (LaunchOptions::flagAppearsIn(launchOpts, entry.flag)) return &entry;
		}
		return nullptr;
	}

	// Pick one matching entry for this AppId and record it into `rules`. The
	// Proton path additionally records the helper .so and registers a session
	// token; the native path stores only the library path. helperSo is unused
	// (and expected empty) when isNative.
	void buildRules(const std::vector<CConfig::LibraryInjectEntry>& entries,
	               uint32_t currentAppId,
	               bool isNative,
	               const std::string& helperSo,
	               LaunchRules& rules)
	{
		const char* tag = isNative ? "LibraryInject(native)" : "ProtonInject";
		std::string launchOpts;
		const CConfig::LibraryInjectEntry* chosen = pickEntry(entries, currentAppId, launchOpts);
		if (!chosen) {
			g_pLog->debug("%s: no matching entry for appId %u (LaunchOptions=\"%s\")\n",
				tag, currentAppId, launchOpts.c_str());
			return;
		}
		if (!std::filesystem::exists(chosen->path)) {
			g_pLog->warn("%s: library not found: %s\n", tag, chosen->path.c_str());
			return;
		}

		rules.isNative = isNative;
		if (chosen->apps.count(currentAppId) > 0)
			rules.byApp[currentAppId] = chosen->path;
		if (!chosen->flag.empty())
			rules.byFlag.emplace_back(chosen->flag, chosen->path);

		if (!isNative) {
			rules.helperSo = helperSo;
			rules.sessionToken = registerPendingSession(currentAppId, chosen->path);
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

		const auto match = findDllForLaunch(argv, envp);
		if (match.libPath.empty() || !match.appId
		 || (!match.isNative && match.helperSo.empty()))
			return g_origExecvpe(file, argv, envp);
		// match.sessionToken (Proton path) was populated by buildProtonRules
		// in the parent (Steam main thread). We're running post-fork in the
		// child here — reading from the rules table works (fork preserves
		// memory); writing to g_pendingSessions would not (parent's map
		// wouldn't see it).

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

		// Proton path requires a session token; if it's missing (helper missing
		// or token registration failed) we cannot inject — fall through.
		if (!match.isNative && match.sessionToken.empty())
			return g_origExecvpe(file, argv, envp);

		// Proton: LD_PRELOAD the helper, which IPC-pulls the user DLL via
		// match.sessionToken. Native: LD_PRELOAD the user's .so directly.
		const std::string& preloadPath = match.isNative ? match.libPath : match.helperSo;

		std::string sessionEntry;
		if (!match.isNative) {
			sessionEntry = std::string(SLS_PROTON_INJECT_SESSION_ENV) + "=" + match.sessionToken;
			g_pLog->debug("ProtonInject: execvpe match appId=%u dll=%s token=%s\n",
				match.appId, match.libPath.c_str(), match.sessionToken.c_str());
		} else {
			g_pLog->debug("LibraryInject(native): execvpe match appId=%u so=%s\n",
				match.appId, match.libPath.c_str());
		}

		// +2 (LD_PRELOAD + optional session) + 1 NULL terminator.
		char** newEnvp = static_cast<char**>(alloca((count + 3) * sizeof(char*)));

		std::string ldPreloadEntry;
		for (int i = 0; i < count; i++) {
			if (startsWith(envp[i], "LD_PRELOAD=")) {
				const char* curPreload = envp[i] + 11;
				if (colonListContains(curPreload, preloadPath))
					ldPreloadEntry = envp[i];
				else
					ldPreloadEntry = std::string(envp[i]) + ":" + preloadPath;
				break;
			}
		}
		if (ldPreloadEntry.empty())
			ldPreloadEntry = "LD_PRELOAD=" + preloadPath;

		int dst = 0;
		bool replacedPreload = false;
		bool replacedSession = false;
		for (int i = 0; i < count; i++) {
			if (startsWith(envp[i], "LD_PRELOAD=")) {
				newEnvp[dst++] = const_cast<char*>(ldPreloadEntry.c_str());
				replacedPreload = true;
			} else if (startsWith(envp[i], SLS_PROTON_INJECT_SESSION_ENV "=")) {
				// Proton: replace with this launch's token. Native: drop any
				// stale session var inherited from a prior Proton exec so it
				// does not leak into the native game's environment.
				if (!match.isNative) {
					newEnvp[dst++] = const_cast<char*>(sessionEntry.c_str());
					replacedSession = true;
				}
			} else {
				newEnvp[dst++] = envp[i];
			}
		}
		if (!replacedPreload)
			newEnvp[dst++] = const_cast<char*>(ldPreloadEntry.c_str());
		if (!match.isNative && !replacedSession)
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

namespace
{
	bool endsWithIgnoreCase(const std::string& s, const char* suffix)
	{
		const size_t n = strlen(suffix);
		if (s.size() < n) return false;
		for (size_t i = 0; i < n; i++) {
			char a = s[s.size() - n + i];
			char b = suffix[i];
			if (a >= 'A' && a <= 'Z') a = static_cast<char>(a + ('a' - 'A'));
			if (b >= 'A' && b <= 'Z') b = static_cast<char>(b + ('a' - 'A'));
			if (a != b) return false;
		}
		return true;
	}

	// Lowercase-only substring search. `needle` MUST already be lowercase.
	bool containsCI(const char* hay, const char* needle)
	{
		if (!hay || !*hay || !needle || !*needle) return false;
		const size_t nlen = strlen(needle);
		for (const char* p = hay; *p; ++p) {
			size_t i = 0;
			for (; i < nlen && p[i]; ++i) {
				char a = p[i];
				if (a >= 'A' && a <= 'Z') a = static_cast<char>(a + ('a' - 'A'));
				if (a != needle[i]) break;
			}
			if (i == nlen) return true;
		}
		return false;
	}

	// Native shared library match: ".so", or ".so.N", or ".so.N.M[.K...]"
	// (SONAME-style versioned libraries — e.g. libfoo.so.6, libssl.so.3.0.2).
	// Accepts any number of dot-separated numeric components after .so.
	bool looksLikeNativeLib(const std::string& p)
	{
		const size_t pos = p.rfind(".so");
		if (pos == std::string::npos) return false;
		size_t i = pos + 3;
		if (i == p.size()) return true; // bare .so
		while (i < p.size()) {
			if (p[i] != '.') return false;
			++i;
			const size_t digitsStart = i;
			while (i < p.size() && p[i] >= '0' && p[i] <= '9') ++i;
			if (i == digitsStart) return false; // ".so." with no digits
		}
		return true;
	}

	void installRules(uint32_t appId,
	                  const std::vector<CConfig::LibraryInjectEntry>& dllEntries,
	                  const std::vector<CConfig::LibraryInjectEntry>& soEntries,
	                  const std::string& cfgDir)
	{
		dropPendingSessionsForApp(appId);

		if (dllEntries.empty() && soEntries.empty()) {
			eraseLaunchRules(appId);
			return;
		}

		LaunchRules rules;
		rules.appId = appId;

		if (!dllEntries.empty()) {
			const std::string helperSo = findHelperSo("sls_proton_inject.so", cfgDir);
			if (helperSo.empty()) {
				g_pLog->warn("ProtonInject: sls_proton_inject.so not found\n");
			} else if (ensureControlServer()) {
				buildRules(dllEntries, appId, /*isNative*/false, helperSo, rules);
			}
		}

		if (!soEntries.empty()) {
			buildRules(soEntries, appId, /*isNative*/true, /*helperSo*/{}, rules);
		}

		if (rules.byApp.empty() && rules.byFlag.empty()) {
			eraseLaunchRules(appId);
			return;
		}

		if (!g_hooked) {
			g_hooked = installHooks();
			if (!g_hooked) { eraseLaunchRules(appId); return; }
		}

		{
			std::lock_guard<std::mutex> lock(g_launchRulesMu);
			g_launchRulesByApp[appId] = rules;
		}

		const char* tag = rules.isNative ? "LibraryInject(native)" : "ProtonInject";
		auto appIt = rules.byApp.find(appId);
		if (appIt != rules.byApp.end())
			g_pLog->info("%s: appId %u -> %s (App rule)\n", tag, appId, appIt->second.c_str());
		else if (!rules.byFlag.empty())
			g_pLog->info("%s: appId %u -> %s (Flag=\"%s\" from LaunchOptions)\n",
				tag, appId, rules.byFlag.front().second.c_str(),
				rules.byFlag.front().first.c_str());
	}
}

bool LibraryInject::isEnabled()
{
	return g_config.libraryInject.read(
		[](const auto& cfg) { return !cfg.libs.empty(); });
}

void LibraryInject::onLaunchApp(uint32_t appId)
{
	const auto cfg = g_config.libraryInject.get();
	if (cfg.libs.empty()) {
		// No config at all: still clear lingering proton rules so a
		// FileWatcher-driven config edit that removed every entry
		// stops injecting on the next launch.
		clearLaunchRules();
		dropPendingSessionsForApp(appId);
		return;
	}

	// Partition entries by Path extension first.
	std::vector<CConfig::LibraryInjectEntry> dllEntries;
	std::vector<CConfig::LibraryInjectEntry> soEntries;
	for (const auto& e : cfg.libs) {
		if (endsWithIgnoreCase(e.path, ".dll"))  dllEntries.push_back(e);
		else if (looksLikeNativeLib(e.path))     soEntries.push_back(e);
		else g_pLog->warn("LibraryInject: ignoring entry with unknown extension: %s\n", e.path.c_str());
	}

	// Skip the launch entirely until IClientCompat::RunIPCFrame has captured
	// g_pClientCompat. The race window is the first frames after Steam start.
	if (!g_pClientCompat) {
		g_pLog->warn("LibraryInject: appId %u not injected — IClientCompat not captured yet "
		             "(launched too early after Steam start); relaunch the game.\n", appId);
		clearLaunchRules();
		dropPendingSessionsForApp(appId);
		return;
	}

	// Steam Linux Runtime ("SteamLinuxRuntime_sniper" etc.) and native
	// emulator wrappers (luxtorpeda, boxtron, roberta) return non-empty
	// compat-tool names but launch native ELF children, so a non-empty
	// name alone can't be the test. Match on "proton"/"wine" substrings
	// instead: every Wine-based compat tool (Valve Proton, GE-Proton,
	// proton-tkg, Wine-GE, wine-tkg) carries one of those tokens, while
	// SLR and native wrappers carry neither. Unknown tools default to
	// native — the safer miss direction (skip .dll injection vs. wipe a
	// configured .so rule).
	const char* tool = g_pClientCompat->getCompatToolName(appId);
	const bool isWindowsCompat = containsCI(tool, "proton") || containsCI(tool, "wine");
	g_pLog->debug("LibraryInject: appId %u compat-tool=\"%s\" -> %s\n",
		appId, tool ? tool : "", isWindowsCompat ? "Windows-compat" : "Native");
	if (isWindowsCompat) soEntries.clear();
	else                 dllEntries.clear();

	installRules(appId, dllEntries, soEntries, cfg.dir);
}

namespace
{
	std::mutex g_runningAppsMu;
	std::unordered_set<uint32_t> g_lastRunningApps;

	// Recently-issued tokens within this window are protected from
	// GamesPlayed-diff drops — covers a race where Steam queues the
	// "game stopped" CMsgClientGamesPlayed but the user is already
	// re-launching the same app and our new token would otherwise be
	// dropped just before execvpe.
	inline constexpr int64_t kGamesPlayedDropProtectSec = 5;
}

void LibraryInject::onGamesPlayedUpdate(const std::unordered_set<uint32_t>& runningAppIds)
{
	std::unordered_set<uint32_t> stopped;
	{
		std::lock_guard<std::mutex> lock(g_runningAppsMu);
		for (uint32_t appId : g_lastRunningApps) {
			if (!runningAppIds.count(appId)) stopped.insert(appId);
		}
		g_lastRunningApps = runningAppIds;
	}
	if (stopped.empty()) return;

	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	const int64_t nowSec = static_cast<int64_t>(ts.tv_sec);

	for (uint32_t appId : stopped) {
		size_t reaped = 0;
		size_t remaining = 0;
		{
			std::lock_guard<std::mutex> lock(g_pendingSessionsMu);
			for (auto it = g_pendingSessions.begin(); it != g_pendingSessions.end(); ) {
				if (it->second.appId == appId
				 && nowSec - it->second.createdAtSec >= kGamesPlayedDropProtectSec) {
					it = g_pendingSessions.erase(it);
					++reaped;
				} else {
					++it;
				}
			}
			remaining = g_pendingSessions.size();
		}
		eraseLaunchRules(appId);
		g_pLog->debug("ProtonInject: GamesPlayed-stopped appId=%u reaped=%zu (pending=%zu)\n",
			appId, reaped, remaining);
	}
}
