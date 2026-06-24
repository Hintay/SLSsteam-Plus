#pragma once

// Consolidated steamclient-drift report.
//
// Multiple subsystems detect signs of layout/selector drift between the build
// SLSsteam was prepared for and the live Steam install (pattern signatures,
// vtable name pool, runtime IPC dispatch). Each individual signal is logged at
// Debug level, then registered here. A single Warn-level summary block is
// emitted ~20s after the first signal so the user sees one notification, not
// one popup per affected method.

namespace DriftReport
{
	// VFThook static name-pool check refused to install: vtable[index] in the
	// scanned IClient* name pool does not match the expected method name.
	void pushStaticVFTMismatch(const char* hookName, unsigned int index, const char* expected, const char* actualAtIndex);

	// VFThook first-call TraceIPC check found the dispatcher routing to a
	// different IPC name and removed the (mistakenly) installed hook.
	void pushDynamicVFTMismatch(const char* hookName, const char* expected, const char* actualIface, const char* actualFn);

	// Pattern signature could not be located in .text and online recovery
	// (if enabled) did not restore it. Optional patterns are reported
	// separately so the user can triage required vs nice-to-have.
	void pushUnresolvedPattern(const char* patternName, bool optional);
}
