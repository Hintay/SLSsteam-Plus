#include "log.hpp"

#include "config.hpp"

#include <cstdlib>
#include <memory>

CLog::CLog(const char* path, bool truncate) : path(path)
{
	const auto mode = truncate
		? (std::ios::out | std::ios::trunc)
		: (std::ios::out | std::ios::app);
	ofstream = std::ofstream(path, mode);
	if (!ofstream.is_open())
	{
		throw std::runtime_error("Unable to open logfile!");
	}
}

CLog::~CLog()
{
	if (ofstream.is_open())
	{
		ofstream.close();
	}
}

//Dirty workaround for not being able to access g_config from __log
LogLevel CLog::getMinLevel()
{
	return static_cast<LogLevel>(g_config.logLevel.get());
}

bool CLog::shouldNotify()
{
	return g_config.notifications.get();
}

CLog* CLog::createDefaultLog()
{
	const char* home = getenv("HOME");
	if (home)
	{
		std::stringstream ss;
		ss << home << "/.SLSsteam.log";

		return new CLog(ss.str().c_str(), /*truncate=*/true);
	}

	return nullptr;
}

CLog* CLog::createDefaultAppendLog()
{
	const char* home = getenv("HOME");
	if (home)
	{
		std::stringstream ss;
		ss << home << "/.SLSsteam.log";

		return new CLog(ss.str().c_str(), /*truncate=*/false);
	}

	return nullptr;
}

std::unique_ptr<CLog> g_pLog;
