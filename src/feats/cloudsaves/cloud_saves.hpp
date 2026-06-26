#pragma once
#include <cstdint>

struct CNetPacket;

namespace CloudSaves {

// Lifecycle (called from main.cpp load()/unload()).
void init();      // create SaveStore + HttpTransfer + RpcEngine; sweep staging
void shutdown();

// Set the current account id (low 32 bits of the SteamID). 0 = unresolved.
void setAccountId(uint32_t accountId);

// True iff CloudSaves should handle this app (Mode==redirect && controlled).
bool handlesApp(uint32_t appId);

// NetPacket send hook: returns true if this was a Cloud.* frame we handled
// (caller must DROP the outbound frame; the fabricated response is queued).
bool onSendFrame(const uint8_t* pubData, uint32_t cubData);

// Pull one ready fabricated response for carrier-borrow injection on recv.
bool nextInjection(const uint8_t*& outData, uint32_t& outSize);

}  // namespace CloudSaves
