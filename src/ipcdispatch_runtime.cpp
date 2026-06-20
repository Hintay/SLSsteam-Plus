#include "ipcdispatch.hpp"
#include "log.hpp"

#include <map>
#include <mutex>
#include <set>

namespace {

std::map<uint32_t, IpcDispatch::IpcHandler> g_registry;
std::set<uint32_t> g_loggedUnmatched;

const uint8_t* packetOf(void* pRead, size_t& lenOut) {
	if (!pRead) return nullptr;
	const uint8_t* p = *reinterpret_cast<const uint8_t* const*>(pRead);
	lenOut = *reinterpret_cast<const uint32_t*>(reinterpret_cast<const uint8_t*>(pRead) + 4);
	return p;
}

}

void IpcDispatch::registerHandler(uint32_t funcHash, IpcHandler handler) {
	g_registry[funcHash] = handler;
}

void IpcDispatch::dispatch(void* pIf, void* pRead, void* pWrite, void* a3, OrigFn original) {
	size_t len = 0;
	const uint8_t* pkt = packetOf(pRead, len);

	Header h;
	if (!parseHeader(pkt, len, h)) {
		original(pIf, pRead, pWrite, a3);
		return;
	}

	auto it = g_registry.find(h.funcHash);
	if (it == g_registry.end()) {
		if (CLog::getMinLevel() <= LogLevel::Debug) {
			static std::mutex logMtx;
			std::lock_guard<std::mutex> lk(logMtx);
			if (g_loggedUnmatched.insert(h.funcHash).second)
				g_pLog->debug("IpcDispatch: unmatched iface=%u funcHash=0x%08x\n", h.interfaceID, h.funcHash);
		}
		original(pIf, pRead, pWrite, a3);
		return;
	}

	IpcCallCtx ctx{ pIf, pRead, pWrite, h.interfaceID, h.funcHash, original, a3 };
	it->second(ctx);
}
