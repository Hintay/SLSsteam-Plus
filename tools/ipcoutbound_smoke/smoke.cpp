// Host-arch smoke test for IpcOutbound::firstFuncHash — the pure byte scanner that locates a
// wrapper's embedded IPC funcHash. Arch-independent (no -m32), so it runs on the dev host.
//   build+run:  make ipcoutbound_smoke
#include "../../src/ipcoutbound.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace
{
	// Append the wrapper pattern  C7 45 <disp> <imm32 LE> 6A 04 50 57 E8  for `imm`.
	void emitFuncHash(std::vector<uint8_t>& v, uint8_t disp, uint32_t imm)
	{
		v.insert(v.end(), { 0xC7, 0x45, disp,
		                    uint8_t(imm), uint8_t(imm >> 8), uint8_t(imm >> 16), uint8_t(imm >> 24),
		                    0x6A, 0x04, 0x50, 0x57, 0xE8 });
	}
}

int main()
{
	// Real IClientApps::GetAppData constants (funcHash then fencepost) from the live binary.
	const uint32_t kFuncHash  = 0x87D25D33;
	const uint32_t kFencepost = 0x89DAA76D;

	// 1) First match in a realistic wrapper (junk prologue, funcHash, then fencepost) is the
	//    funcHash — never the fencepost.
	{
		std::vector<uint8_t> w = { 0x55, 0x89, 0xE5, 0x83, 0xEC, 0x40 }; // push ebp; mov ebp,esp; sub esp
		emitFuncHash(w, 0xF4, kFuncHash);
		emitFuncHash(w, 0xF0, kFencepost);
		uint32_t got = 0;
		assert(IpcOutbound::firstFuncHash(w.data(), w.size(), got));
		assert(got == kFuncHash);
	}

	// 2) No pattern -> false, out untouched.
	{
		std::vector<uint8_t> w(64, 0x90); // all NOPs
		uint32_t got = 0xDEADBEEF;
		assert(!IpcOutbound::firstFuncHash(w.data(), w.size(), got));
		assert(got == 0xDEADBEEF);
	}

	// 3) A C7 45 mov WITHOUT the push/call tail must not match (avoids false positives).
	{
		std::vector<uint8_t> w = { 0xC7, 0x45, 0xFC, 0x01, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90 };
		uint32_t got = 0;
		assert(!IpcOutbound::firstFuncHash(w.data(), w.size(), got));
	}

	// 4) Boundary: a buffer shorter than the 12-byte pattern is rejected.
	{
		std::vector<uint8_t> w; emitFuncHash(w, 0xF4, kFuncHash);
		uint32_t got = 0;
		assert(!IpcOutbound::firstFuncHash(w.data(), 11, got)); // truncated by 1 byte
		assert(IpcOutbound::firstFuncHash(w.data(), w.size(), got) && got == kFuncHash);
	}

	// 5) Null / zero-length safety.
	{
		uint32_t got = 0;
		assert(!IpcOutbound::firstFuncHash(nullptr, 100, got));
		assert(!IpcOutbound::firstFuncHash(reinterpret_cast<const uint8_t*>(""), 0, got));
	}

	std::printf("ipcoutbound_smoke: all assertions passed\n");
	return 0;
}
