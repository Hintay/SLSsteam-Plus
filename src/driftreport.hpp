#pragma once

// Consolidated steamclient-drift report.
//
// Multiple subsystems detect signs of layout/selector drift between the build
// SLSsteam was prepared for and the live Steam install (pattern signatures,
// VtableScan slot resolution). Each individual signal is logged at Debug level,
// then registered here. A single Debug-level summary block is emitted ~20s
// after the first signal so the user sees one notification, not one popup per
// affected method.

namespace DriftReport
{
	// VtableScan could not resolve a hook's (iface, method) to a vtable slot,
	// so installVFT skipped that hook. `actualAtIndex` carries a short reason.
	void pushStaticVFTMismatch(const char* hookName, unsigned int index, const char* expected, const char* actualAtIndex);

	// Pattern signature could not be located in .text and online recovery
	// (if enabled) did not restore it. Optional patterns are reported
	// separately so the user can triage required vs nice-to-have.
	void pushUnresolvedPattern(const char* patternName, bool optional);
}
