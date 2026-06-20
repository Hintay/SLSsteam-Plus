#include "ipcdispatch.hpp"

bool IpcDispatch::parseHeader(const uint8_t* pkt, size_t len, Header& out)
{
	if (!pkt || len < 10)
		return false;
	out.interfaceID = pkt[1];
	out.funcHash =  static_cast<uint32_t>(pkt[6])
	             | (static_cast<uint32_t>(pkt[7]) << 8)
	             | (static_cast<uint32_t>(pkt[8]) << 16)
	             | (static_cast<uint32_t>(pkt[9]) << 24);
	return true;
}
