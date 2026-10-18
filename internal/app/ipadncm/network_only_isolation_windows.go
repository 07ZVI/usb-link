//go:build windows && amd64

package ipadncm

import "errors"

func networkOnlySwitchOn() bool { return connectionPreferences().NetworkOnlyEnabled() }

// Persist the choice, then steer the running worker: on reconciles every
// remembered instance now, off restores every owned node (present or not).
// Outside a running lifecycle only the preference changes; start and exit own
// the rest.
func setNetworkOnlySwitch(on bool) error {
	startupPreferenceMu.Lock()
	defer startupPreferenceMu.Unlock()
	p := connectionPreferences()
	p.NetworkOnlyOff = !on
	if saveConnectionPreferences(p) != nil {
		return errors.New("NETWORK_ONLY_PREFERENCE_SAVE_FAILED")
	}
	if defaultIsolationAdmission() == nil {
		localPhoto.runtimeDefault(on)
	}
	return nil
}
