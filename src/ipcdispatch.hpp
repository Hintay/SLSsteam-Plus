#pragma once

#include <cstddef>
#include <cstdint>

namespace IpcDispatch
{
	struct Header
	{
		uint8_t  interfaceID = 0;
		uint32_t funcHash    = 0;
	};

	bool parseHeader(const uint8_t* pkt, size_t len, Header& out);

	using OrigFn = void(*)(void*, void*, void*, void*);

	struct IpcCallCtx {
		void*    pInterface;
		void*    pRead;
		void*    pWrite;
		uint8_t  interfaceID;
		uint32_t funcHash;
		OrigFn   original;
		void*    a3;
	};
	using IpcHandler = void(*)(IpcCallCtx&);

	inline uint32_t readArgU32(const uint8_t* pkt, unsigned argOffset)
	{
		const uint8_t* a = pkt + 10 + argOffset;
		return static_cast<uint32_t>(a[0]) | (static_cast<uint32_t>(a[1])<<8)
		     | (static_cast<uint32_t>(a[2])<<16) | (static_cast<uint32_t>(a[3])<<24);
	}

	inline const uint8_t* requestPtr(void* pRead)
	{
		return pRead ? *reinterpret_cast<const uint8_t* const*>(pRead) : nullptr;
	}

	inline uint8_t* responsePtr(void* pWrite)
	{
		return pWrite ? *reinterpret_cast<uint8_t**>(pWrite) : nullptr;
	}
	inline uint32_t responseLen(void* pWrite)
	{
		return pWrite ? *reinterpret_cast<const uint32_t*>(reinterpret_cast<const uint8_t*>(pWrite) + 4) : 0;
	}
	inline void writeU32(uint8_t* buf, unsigned off, uint32_t v)
	{
		buf[off + 0] = static_cast<uint8_t>(v);
		buf[off + 1] = static_cast<uint8_t>(v >> 8);
		buf[off + 2] = static_cast<uint8_t>(v >> 16);
		buf[off + 3] = static_cast<uint8_t>(v >> 24);
	}

	void registerHandler(uint32_t funcHash, IpcHandler handler);
	void dispatch(void* pInterface, void* pRead, void* pWrite, void* a3, OrigFn original);
}
