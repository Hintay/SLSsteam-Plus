#pragma once

// Tiny helper for SLSsteam's outbound IClient calls. Resolves the slot via
// VtableScan::slotOf(iface, method) at the call site and dispatches through
// the live vtable. No funcHash math, no name pools — VtableScan is the single
// source of truth (see src/vtablescan.cpp).
namespace IpcOutbound
{
	// Invoke vtable[index](this, args...) at an already-known index:
	//   static const int idx = VtableScan::slotOf("IClientApps", "GetAppData");
	//   return IpcOutbound::callAt<Sig>(idx, this, args...);
	template <typename tFN, typename... Args>
	auto callAt(int index, void* thisPtr, Args... args)
	{
		const auto fn = reinterpret_cast<tFN>((*reinterpret_cast<void***>(thisPtr))[index]);
		return fn(thisPtr, args...);
	}
}
