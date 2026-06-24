#pragma once

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <memory>
#include <mutex>
#include <openssl/sha.h>
#include <shared_mutex>
#include <sstream>
#include <unordered_set>

enum class LogLevel : unsigned int
{
	//TODO: Add Trace without breaking configs and without using -1 for Once
	Once,
	Debug,
	Info,
	NotifyShort,
	NotifyLong,
	Warn,
	None
};

class CLog
{
	std::ofstream ofstream;
	std::unordered_set<std::string> msgHist {};
	std::shared_mutex mutex;

	constexpr const char* logLvlToStr(LogLevel& lvl)
	{
		switch(lvl)
		{
			case LogLevel::Once:
				return "Once";
			case LogLevel::Debug:
				return "Debug";
			case LogLevel::Info:
				return "Info";
			case LogLevel::NotifyShort:
			case LogLevel::NotifyLong:
				return "Notify";
			case LogLevel::Warn:
				return "Warn";

			//Shut gcc warning up
			default:
				return "Unknown";
		}
	}

	template<typename ...Args>
	__attribute__((hot))
	void __log(LogLevel lvl, const char* msg, Args... args)
	{
		if (lvl < getMinLevel())
		{
			return;
		}

		std::string formatted;
		if constexpr (sizeof...(Args) == 0)
		{
			formatted = msg;
		}
		else
		{
			size_t size = snprintf(nullptr, 0, msg, args...) + 1; //Allocate one more byte for zero termination
			formatted.resize(size);
			snprintf(formatted.data(), size, msg, args...);
		}

		std::stringstream notifySS;

		switch(lvl)
		{
			//TODO: Fix possible breakage when there's only one " in formatted
			case LogLevel::NotifyShort:
				notifySS << "notify-send -t 10000 -u \"normal\" \"SLSsteam\" \"" << formatted.c_str() << "\"";
				break;
			case LogLevel::NotifyLong:
				notifySS << "notify-send -t 30000 -u \"normal\" \"SLSsteam\" \"" << formatted.c_str() << "\"";
				break;
			case LogLevel::Warn:
				notifySS << "notify-send -u \"critical\" \"SLSsteam\" \"" << formatted.c_str() << "\"";
				break;

			default:
				break;

		}

		const std::string notifyCmd = notifySS.str();
		if (shouldNotify() && notifyCmd.size() > 0)
		{
			const int rc = system(notifyCmd.c_str());
			(void)rc;
			debug("system(\"%s\")\n", notifyCmd.c_str());
		}

		const auto lock = std::unique_lock(mutex);

		if (lvl == LogLevel::Once)
		{
			for(const auto& oldMsg : msgHist)
			{
				if (oldMsg == formatted)
				{
					return;
				}
			}

			msgHist.emplace(formatted);
		}

		const auto now = std::chrono::system_clock::now();
		const auto seconds = std::chrono::system_clock::to_time_t(now);
		const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
		std::tm localTime {};
		localtime_r(&seconds, &localTime);

		ofstream << "[" << std::put_time(&localTime, "%F %T") << "."
			<< std::setfill('0') << std::setw(3) << millis << std::setfill(' ')
			<< "] [" << logLvlToStr(lvl) << "] " << formatted.c_str();
		if (lvl == LogLevel::NotifyShort || lvl == LogLevel::NotifyLong)
		{
			ofstream << "\n";
		}

		ofstream.flush();
	}

public:
	std::string path;

	// truncate=true wipes the file at open (parent's per-Steam-session reset).
	// truncate=false opens in append mode (O_APPEND) — required when a child
	// process (e.g., OnlinePatterns helper) re-opens the parent's log file:
	// per-write atomicity from the kernel keeps both processes' lines intact.
	CLog(const char* path, bool truncate = true);
	~CLog();

	template<typename ...Args>
	constexpr void once(const char* msg, Args... args)
	{
		__log(LogLevel::Once, msg, args...);
	}

	template<typename ...Args>
	constexpr void debug(const char* msg, Args... args)
	{
		__log(LogLevel::Debug, msg, args...);
	}

	template<typename ...Args>
	constexpr void info(const char* msg, Args... args)
	{
		__log(LogLevel::Info, msg, args...);
	}

	template<typename ...Args>
	constexpr void notify(const char* msg, Args... args)
	{
		__log(LogLevel::NotifyShort, msg, args...);
	}

	template<typename ...Args>
	constexpr void notifyLong(const char* msg, Args... args)
	{
		__log(LogLevel::NotifyLong, msg, args...);
	}

	template<typename ...Args>
	constexpr void warn(const char* msg, Args... args)
	{
		__log(LogLevel::Warn, msg, args...);
	}

	//Do not include config.hpp in this header, otherwise things will break :) (proly due to recursive inclusion)
	static LogLevel getMinLevel();
	static bool shouldNotify();
	static CLog* createDefaultLog();
	// Same path as createDefaultLog but append-only. Use this when an
	// already-running SLSsteam session may also be writing to the file.
	static CLog* createDefaultAppendLog();
};

extern std::unique_ptr<CLog> g_pLog;
