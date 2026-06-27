#pragma once

#include <cstdint>

// Wrapper around IClientCompat::GetCompatToolName(appId).
// Returns the configured compat-tool name for an app: empty string when the
// app is set to run natively, non-empty when a Proton/SLR tool is selected.
class IClientCompat
{
public:
	const char* getCompatToolName(uint32_t appId);
};

extern IClientCompat* g_pClientCompat;
