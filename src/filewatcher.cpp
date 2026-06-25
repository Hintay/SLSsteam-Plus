#include "filewatcher.hpp"

#include "log.hpp"

#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <string>


//TODO: Investigate why gcc complains when put into CFileWatcher itself
void* watchLoop(void* args)
{
	auto watcher = reinterpret_cast<CFileWatcher*>(args);
	g_pLog->debug("Started FileWatcher %u\n", watcher->notifyFd);

	// Buffer must hold at least one event + its name; loop over all events the
	// kernel returns per read (directory watches can coalesce several).
	char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
	while(watcher->running.load())
	{
		pollfd pfd {};
		pfd.fd = watcher->notifyFd;
		pfd.events = POLLIN;

		const int ready = poll(&pfd, 1, 250);
		if (!watcher->running.load())
		{
			break;
		}

		if (ready <= 0 || !(pfd.revents & POLLIN))
		{
			continue;
		}

		ssize_t len = read(watcher->notifyFd, buf, sizeof(buf));
		if (len <= 0)
		{
			continue;
		}

		for (char* p = buf; p < buf + len; )
		{
			auto* ev = reinterpret_cast<struct inotify_event*>(p);
			const auto it = watcher->fileFdMap.find(ev->wd);
			std::string path = it != watcher->fileFdMap.end() ? it->second : "";
			// For a directory watch, ev->name is the entry within the dir.
			if (ev->len > 0 && !path.empty())
			{
				path += '/';
				path += ev->name;
			}
			g_pLog->debug("inotify %u(%s) -> %u\n", ev->wd, path.c_str(), ev->mask);
			watcher->onModify(path, ev->mask);
			p += sizeof(struct inotify_event) + ev->len;
		}
	}

	return nullptr;
}

CFileWatcher::CFileWatcher(FileModifyEvent_t onModify)
{
	this->onModify = onModify;

	notifyFd = inotify_init();
	if (notifyFd == -1)
	{
		g_pLog->warn("inotify_init failed\n");
	}
	else
	{
		g_pLog->debug("Created notify fd %i\n", notifyFd);
	}
}

CFileWatcher::~CFileWatcher()
{
	if (started)
	{
		stop();
	}

	if (notifyFd != -1)
	{
		for(const auto& fd : fileFdMap)
		{
			if (fd.first == -1)
			{
				continue;
			}

			inotify_rm_watch(notifyFd, fd.first);
		}

		close(notifyFd);
		notifyFd = -1;
	}
}

bool CFileWatcher::addFile(const char* path)
{
	int fd = inotify_add_watch(notifyFd, path, IN_MODIFY);
	if (fd == -1)
	{
		return false;
	}

	fileFdMap[fd] = path;
	g_pLog->debug("Added %s to FileWatcher %i\n", path, notifyFd);
	return fd != -1;
}

bool CFileWatcher::addDirectory(const char* path)
{
	int fd = inotify_add_watch(notifyFd, path,
	    IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM);
	if (fd == -1)
	{
		return false;
	}

	fileFdMap[fd] = path;
	g_pLog->debug("Added dir %s to FileWatcher %i\n", path, notifyFd);
	return true;
}

bool CFileWatcher::start()
{
	if (started || notifyFd == -1)
	{
		return false;
	}

	running.store(true);
	int code = pthread_create(&watchThread, nullptr, &watchLoop, this);
	if (code != 0)
	{
		running.store(false);
		return false;
	}

	started = true;
	return code == 0;
}

void CFileWatcher::stop()
{
	if (!started)
	{
		return;
	}

	running.store(false);
	pthread_join(watchThread, nullptr);
	started = false;
}
