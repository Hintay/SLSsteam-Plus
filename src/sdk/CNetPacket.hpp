#pragma once
#include <cstdint>
#include <cstddef>

// Steam's raw on-wire message prefix: an 8-byte MsgHdr precedes the protobuf
// header and protobuf body inside a network packet payload. A protobuf message
// has kMsgHdrProtoFlag OR'd into eMsg.
struct MsgHdr {
    uint32_t eMsg;          // EMsg, OR'd with kMsgHdrProtoFlag for protobuf messages
    uint32_t headerLength;  // byte length of the protobuf header that follows
};
static constexpr uint32_t kMsgHdrProtoFlag = 0x80000000u;

// CCMConnection's network packet. Field layout (m_pubData@+0x0C, m_cubData@+0x10)
// matches the CCMConnection::RecvPkt -> classifier disassembly of the 2026.10.14
// client (reads [pkt+0xC]/[pkt+0x10]; older clients used +0x4/+0x8). Only the
// fields the request-code and achievements hooks touch are modeled.
struct CNetPacket {
    uint8_t  __pad_0x0[0xC];  // +0x00
    uint8_t* m_pubData;       // +0x0C  — MsgHdr + protobuf header + protobuf body
    uint32_t m_cubData;       // +0x10
    // remaining fields intentionally omitted
};
static_assert(offsetof(CNetPacket, m_pubData) == 0x0C, "CNetPacket::m_pubData offset");
static_assert(offsetof(CNetPacket, m_cubData) == 0x10, "CNetPacket::m_cubData offset");
