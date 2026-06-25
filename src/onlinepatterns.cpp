#include "onlinepatterns.hpp"

#include "curl.hpp"
#include "globals.hpp"
#include "log.hpp"
#include "patterns.hpp"   // for PATTERN_BAKED_HASH (extern, via patterns.gen.hpp)
#include "utils.hpp"

#include <toml++/toml.hpp>

#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#include <filesystem>
#include <poll.h>
#include <spawn.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace
{
	constexpr const char* kUrl =
		"https://raw.githubusercontent.com/Hintay/SLSsteam-Plus/refs/heads/main/res/patterns.toml";
	// curl timeouts cap at connect=3s + total=5s; the helper itself adds
	// fork/exec/ld.so overhead. With i386-linux-gnu-true (DT_NEEDED=libc.so.6
	// only) that overhead is ~10ms; the 10s ceiling absorbs slow networks and
	// the fallback to /proc/self/exe if steam-runtime-tools-0 is missing
	// (Steam binary + its many DT_NEEDED can take 2-3s to map).
	constexpr int kFetchTimeoutMs = 10000;
	constexpr const char* kHelperEnv = "SLSSTEAM_HELPER";
	constexpr const char* kHelperMode = "onlinepatterns";
	constexpr const char* kProcSelfExe = "/proc/self/exe";
	// Steam ships several tiny 32-bit ELFs we can hijack as bootstrap targets
	// for our LD_AUDIT child. They all exit cleanly when our la_preinit
	// `_exit(runFetchHelper())`s before main(). Listed in order of preference:
	// smallest dep set first, with diverse install paths so a Steam reorg of
	// one path doesn't break the others. All four verified on Deck to load
	// our auditor + fetch 9 KB toml.
	//
	// Paths are relative to the steamclient.so install: <steam_root>/ubuntu12_32/...
	constexpr const char* kHelperCandidatesRelToSteamClient[] = {
		// steam-runtime-tools-0 multi-arch stubs — explicitly designed as
		// "I just need a tiny 32-bit ELF" use cases. DT_NEEDED=libc only.
		"steam-runtime/usr/libexec/steam-runtime-tools-0/i386-linux-gnu-true",
		"steam-runtime/usr/libexec/steam-runtime-tools-0/i386-linux-gnu-exec",
		// Steam UI overlay loader — stable top-level path, ships with every
		// Steam install. DT_NEEDED=libdl+libc.
		"gameoverlayui",
		// Process reaper — same top-level path. DT_NEEDED=pthread+libc.
		"reaper",
	};

	void closeIfOpen(int& fd)
	{
		if (fd >= 0)
		{
			close(fd);
			fd = -1;
		}
	}

	bool setCloseOnExec(int fd)
	{
		const int flags = fcntl(fd, F_GETFD);
		return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
	}

	bool setNonBlocking(int fd)
	{
		const int flags = fcntl(fd, F_GETFL);
		return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
	}

	bool envStartsWith(const char* env, const char* name)
	{
		const size_t len = strlen(name);
		return strncmp(env, name, len) == 0 && env[len] == '=';
	}

	std::string currentLibraryPath()
	{
		Dl_info info {};
		if (dladdr(reinterpret_cast<void*>(&OnlinePatterns::fetchAndParse), &info) == 0 || !info.dli_fname)
			return {};
		return info.dli_fname;
	}

	void buildHelperEnvironment(const std::string& soPath, std::vector<std::string>& storage, std::vector<char*>& envp)
	{
		// Steam main puts steam-runtime/pinned_libs_32 ahead of /usr/lib32 in
		// LD_LIBRARY_PATH. The pinned libcurl.so.4 (Steam runtime, built when
		// openssl was an older major) only exports CURL_OPENSSL_3. Our auditor
		// is linked against curl 8.19 with openssl 3, so it imports versioned
		// CURL_OPENSSL_4 symbols. If ld.so picks pinned_libs_32 first the
		// audit interface load fails with "version `CURL_OPENSSL_4' not found"
		// and the helper child silently exits 0 with empty stdout.
		//
		// Prepending /usr/lib32 makes the host libcurl.so.4 (which is the
		// newer build with CURL_OPENSSL_4) win the search. Verified on Deck
		// via posix_spawn(i386-linux-gnu-true) → 9 KB toml fetched.
		std::string existingLdLibPath;
		for (char** env = environ; env && *env; ++env)
		{
			if (envStartsWith(*env, "LD_AUDIT") || envStartsWith(*env, kHelperEnv))
				continue;
			if (envStartsWith(*env, "LD_LIBRARY_PATH"))
			{
				existingLdLibPath = std::string(*env + sizeof("LD_LIBRARY_PATH=") - 1);
				continue;
			}
			storage.emplace_back(*env);
		}

		storage.emplace_back(std::string("LD_AUDIT=") + soPath);
		storage.emplace_back(std::string(kHelperEnv) + "=" + kHelperMode);
		std::string newLdLibPath = "/usr/lib32";
		if (!existingLdLibPath.empty())
		{
			newLdLibPath += ":";
			newLdLibPath += existingLdLibPath;
		}
		storage.emplace_back("LD_LIBRARY_PATH=" + newLdLibPath);

		envp.reserve(storage.size() + 1);
		for (auto& entry : storage)
			envp.push_back(entry.data());
		envp.push_back(nullptr);
	}

	// Pick the smallest 32-bit ELF that ld.so can load our auditor into. We
	// walk a list of Steam-shipped 5-8 KB candidates in preference order and
	// fall back to /proc/self/exe (the ~10 MB Steam binary) if every
	// candidate is missing — defensive against Steam reorgs.
	std::string resolveHelperExe()
	{
		if (!g_modSteamClient.path[0])
			return kProcSelfExe;
		namespace fs = std::filesystem;
		const fs::path parent = fs::path(g_modSteamClient.path).parent_path();
		for (const char* rel : kHelperCandidatesRelToSteamClient)
		{
			const fs::path candidate = parent / rel;
			struct stat st {};
			if (stat(candidate.c_str(), &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & S_IXUSR))
				return candidate.string();
		}
		return kProcSelfExe;
	}

	int spawnSelfFetch(int stdoutFd, posix_spawn_file_actions_t& actions, pid_t& pid,
	                   std::string& execPathOut)
	{
		posix_spawn_file_actions_init(&actions);

		const std::string soPath = currentLibraryPath();
		if (soPath.empty())
			return ENOENT;

		execPathOut = resolveHelperExe();

		posix_spawn_file_actions_adddup2(&actions, stdoutFd, STDOUT_FILENO);
		posix_spawn_file_actions_addclose(&actions, stdoutFd);

		char* argv[] = {
			execPathOut.data(),
			nullptr
		};

		std::vector<std::string> envStorage;
		std::vector<char*> envp;
		buildHelperEnvironment(soPath, envStorage, envp);

		return posix_spawn(&pid, execPathOut.c_str(), &actions, nullptr, argv, envp.data());
	}

	bool fetchBodyInChildProcess(std::string& body, int& resultCode)
	{
		resultCode = -1;

		int pipeFds[2] = { -1, -1 };
		if (pipe(pipeFds) != 0)
		{
			resultCode = errno;
			return false;
		}

		setCloseOnExec(pipeFds[0]);
		setCloseOnExec(pipeFds[1]);
		setNonBlocking(pipeFds[0]);

		posix_spawn_file_actions_t actions;
		pid_t pid = -1;
		std::string execPath;
		const int spawnRc = spawnSelfFetch(pipeFds[1], actions, pid, execPath);
		posix_spawn_file_actions_destroy(&actions);
		closeIfOpen(pipeFds[1]);

		if (spawnRc != 0)
		{
			closeIfOpen(pipeFds[0]);
			resultCode = spawnRc;
			return false;
		}
		if (g_pLog)
			g_pLog->debug("OnlinePatterns: helper spawned pid=%d via %s\n", pid, execPath.c_str());

		const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kFetchTimeoutMs);
		bool stdoutOpen = true;
		bool childDone = false;
		int childStatus = 0;

		while (stdoutOpen || !childDone)
		{
			if (!childDone)
			{
				const pid_t waitRc = waitpid(pid, &childStatus, WNOHANG);
				if (waitRc == pid)
					childDone = true;
			}

			if (std::chrono::steady_clock::now() >= deadline)
			{
				kill(pid, SIGKILL);
				waitpid(pid, &childStatus, 0);
				closeIfOpen(pipeFds[0]);
				resultCode = -2;
				return false;
			}

			if (stdoutOpen)
			{
				char buffer[4096];
				while (true)
				{
					const ssize_t n = read(pipeFds[0], buffer, sizeof(buffer));
					if (n > 0)
					{
						body.append(buffer, static_cast<size_t>(n));
						continue;
					}
					if (n == 0)
					{
						stdoutOpen = false;
						closeIfOpen(pipeFds[0]);
					}
					else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
					{
						// Non-recoverable read error (EIO, EBADF, ...). Without
						// this branch the outer loop would burn its remaining
						// budget polling a dead pipe; close it and let the
						// waitpid/deadline path take over.
						stdoutOpen = false;
						closeIfOpen(pipeFds[0]);
					}
					break;
				}

				if (stdoutOpen)
				{
					const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
						deadline - std::chrono::steady_clock::now()).count();
					pollfd pfd { pipeFds[0], POLLIN | POLLHUP, 0 };
					poll(&pfd, 1, static_cast<int>(std::min<long long>(remaining, 100)));
				}
			}
			else if (!childDone)
			{
				poll(nullptr, 0, 10);
			}
		}

		if (WIFEXITED(childStatus))
			resultCode = WEXITSTATUS(childStatus);
		else if (WIFSIGNALED(childStatus))
			resultCode = -WTERMSIG(childStatus);

		return resultCode == 0 && !body.empty();
	}

	MemHlp::SigFollowMode parseFollow(const std::string& s)
	{
		if (s == "Relative") return MemHlp::SigFollowMode::Relative;
		if (s == "PrologueUpwards") return MemHlp::SigFollowMode::PrologueUpwards;
		return MemHlp::SigFollowMode::None;
	}

	std::vector<uint8_t> parsePrologue(const std::string& hex)
	{
		const auto raw = MemHlp::patternToBytes(hex.c_str());
		std::vector<uint8_t> out;
		for (const auto b : raw)
			if (b >= 0) out.push_back(static_cast<uint8_t>(b));
		return out;
	}

	// Parse a version key: "current" → 0 (latest), numeric string → that version.
	// Returns false for unrecognisable keys (caller should skip).
	bool parseVersionKey(const std::string& key, uint32_t& outVersion)
	{
		if (key == "current") { outVersion = 0; return true; }
		try { outVersion = static_cast<uint32_t>(std::stoul(key)); return true; }
		catch (...) { return false; }
	}

	// Parse a pattern spec table. The "pattern" field is either a plain string
	// (single entry, maxVersion=0) or a sub-table with "current" + version keys.
	// Shared fields (follow, prologue) are read from the parent spec table.
	void parsePatternSpec(const toml::table& spec, const std::string& key,
	                      std::map<std::string, std::vector<OnlinePatterns::Entry>>& byName)
	{
		const auto follow = parseFollow(spec["follow"].value_or(std::string("None")));
		std::vector<uint8_t> prologue;
		if (auto p = spec["prologue"].value<std::string>())
			prologue = parsePrologue(*p);

		auto& vec = byName[key];

		if (auto s = spec["pattern"].value<std::string>())
		{
			vec.push_back({ *s, follow, prologue, 0 });
		}
		else if (auto* tbl = spec["pattern"].as_table())
		{
			for (const auto& [vk, vv] : *tbl)
			{
				auto sig = vv.value<std::string>();
				if (!sig) continue;
				uint32_t maxVer;
				if (!parseVersionKey(std::string(vk.str()), maxVer)) continue;
				vec.push_back({ *sig, follow, prologue, maxVer });
			}
		}
	}

}

OnlinePatterns::Overrides OnlinePatterns::fetchAndParse()
{
	Overrides ov;

	std::string body;
	int rc = 0;
	if (!fetchBodyInChildProcess(body, rc))
	{
		g_pLog->debug("OnlinePatterns: self-helper fetch failed rc=%d\n", rc);
		return ov;
	}

	try
	{
		if (Utils::sha256OfString(body) == std::string(PATTERN_BAKED_HASH))
		{
			g_pLog->debug("OnlinePatterns: online hash == baked, skipping\n");
			return ov;
		}
		auto root = toml::parse(body);

		if (auto* patterns = root["Patterns"].as_table())
		{
			for (const auto& [modKey, modVal] : *patterns)
			{
				const auto* mod = modVal.as_table();
				if (!mod) continue;
				for (const auto& [fnKey, fnVal] : *mod)
				{
					const std::string key(fnKey.str());
					if (auto* tbl = fnVal.as_table())
						parsePatternSpec(*tbl, key, ov.byName);
				}
			}
		}

		ov.usable = true;
		g_pLog->info("OnlinePatterns: parsed %zu pattern entries\n", ov.byName.size());
	}
	catch (...)
	{
		g_pLog->info("OnlinePatterns: parse failed, ignoring online file\n");
		ov.usable = false;
	}

	return ov;
}

bool OnlinePatterns::isFetchHelperRequested()
{
	const char* mode = getenv(kHelperEnv);
	return mode && strcmp(mode, kHelperMode) == 0;
}

int OnlinePatterns::runFetchHelper()
{
	// We run in a posix_spawn'd child before main(), so setup() never installed
	// the logger. Bring it up here so Curl::request / sub-calls can log into
	// the same ~/.SLSsteam.log as the parent. Append-mode is critical: the
	// trunc-mode default constructor would zero-fill the file from offset 0,
	// destroying every log line the parent has already written.
	if (!g_pLog)
		g_pLog = std::unique_ptr<CLog>(CLog::createDefaultAppendLog());

	std::string body;
	long status = 0;

	Curl::RequestOptions options;
	options.timeoutConnectMs = 3000;
	options.timeoutTotalMs = 5000;
	options.httpsOnlyRedirects = true;

	const int rc = Curl::request("GET", kUrl, {}, {}, body, status, options);
	if (rc != 0 || status != 200 || body.empty())
	{
		if (g_pLog)
			g_pLog->debug("OnlinePatterns helper: curl failed rc=%d status=%ld bytes=%zu\n",
				rc, status, body.size());
		return 1;
	}

	const char* data = body.data();
	size_t left = body.size();
	while (left > 0)
	{
		const ssize_t written = write(STDOUT_FILENO, data, left);
		if (written <= 0)
			return 2;
		data += written;
		left -= static_cast<size_t>(written);
	}

	return 0;
}
