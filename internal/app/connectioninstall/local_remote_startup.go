//go:build usblink_local_remote

package connectioninstall

// The manager lock serializes this state. Failed network cleanup blocks USB
// authorization, not independent owner-protected diagnostic preferences.
type localRemoteStartupCleanup struct {
	firstError    error
	localPending  bool
	legacyPending bool
}

func (s *localRemoteStartupCleanup) record(stage string, err error) {
	if err == nil {
		return
	}
	if s.firstError == nil {
		s.firstError = remoteInitializationFailure(stage, err)
	}
	if stage == "local_firewall" {
		s.localPending = true
	}
	if stage == "legacy_firewall" {
		s.legacyPending = true
	}
}

func (s *localRemoteStartupCleanup) pending() bool { return s.localPending || s.legacyPending }

func (s *localRemoteStartupCleanup) prepare(enabled bool, desired func() bool, local, legacy, activate func() error) error {
	// Every toggle already requires local cleanup; retrying startup must not
	// duplicate it or reuse credentials from a failed enable.
	if err := local(); err != nil {
		s.record("local_firewall", err)
		return remoteInitializationFailure("local_firewall", err)
	}
	s.localPending = false
	if s.legacyPending {
		if err := legacy(); err != nil {
			return remoteInitializationFailure("legacy_firewall", err)
		}
		s.legacyPending = false
	}
	// Off can revoke intent while cleanup holds the manager lock.
	if !enabled || !desired() {
		return nil
	}
	return activate()
}
