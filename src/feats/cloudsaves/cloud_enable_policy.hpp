#pragma once
#include <cstddef>
#include <cstdint>
#include <unordered_set>

namespace CloudSaves {

// Scan a sharedconfig.vdf text buffer and insert into `out` every appid whose
// block contains "cloudenabled" "0". Brace-aware: tracks the nearest enclosing
// quoted numeric key as the current appid. Absent or "1" -> not inserted.
void ParseDisabledCloudApps(const char* text, size_t len,
                            std::unordered_set<uint32_t>& out);

// Decide IsCloudEnabledForApp for a controlled app in Redirect mode.
//   origEnabled    : what Steam's native function returned
//   userDisabled   : app is in the explicit-OFF set
//   accountMasterOn: account-level Steam Cloud master is on
// Rule: already-on stays on; explicit user-off respected; global-off respected;
// otherwise force on (neutralize the hidecloudui enable-gate).
bool DecideCloudEnabled(bool origEnabled, bool userDisabled, bool accountMasterOn);

}  // namespace CloudSaves
