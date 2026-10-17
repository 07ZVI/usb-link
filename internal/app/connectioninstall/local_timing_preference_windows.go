//go:build windows && amd64 && usblink_local_remote

package connectioninstall

import (
	"fmt"
	"os"
	"path/filepath"
)

// Kept separate from the master schema so earlier installers can still read
// their own setting. This record grants no token, certificate or install consent.
func (m *RemoteManager) ReadLocalTimingPreference() (string, error) {
	sid, e := m.localDebugOwner()
	if e != nil {
		return "normal", e
	}
	name, e := localTimingPreferenceName(sid)
	if e != nil {
		return "normal", e
	}
	b, e := coreProtectedReadBounded(filepath.Join(m.root, name), false, true, 1024)
	if os.IsNotExist(e) {
		return "normal", nil
	}
	if e != nil {
		return "normal", fmt.Errorf("LOCAL_TIMING_PREFERENCE_READ_FAILED")
	}
	mode, e := decodeLocalTimingPreference(b, sid)
	if e != nil {
		return "normal", e
	}
	current, e := m.localDebugOwner()
	if e != nil || current != sid {
		return "normal", fmt.Errorf("LOCAL_TIMING_OWNER_CHANGED")
	}
	return mode, nil
}
func (m *RemoteManager) SaveLocalTimingPreference(mode string) error {
	if !validLocalTimingMode(mode) {
		return fmt.Errorf("LOCAL_TIMING_MODE_INVALID")
	}
	sid, e := m.localDebugOwner()
	if e != nil {
		return e
	}
	if _, e = coreProtectedRead(m.root, true, false); e != nil {
		return fmt.Errorf("LOCAL_TIMING_PREFERENCE_PROTECTION_FAILED")
	}
	name, e := localTimingPreferenceName(sid)
	if e != nil {
		return e
	}
	path := filepath.Join(m.root, name)
	if _, e = coreProtectedReadBounded(path, false, true, 1024); e != nil && !os.IsNotExist(e) {
		return fmt.Errorf("LOCAL_TIMING_PREFERENCE_PROTECTION_FAILED")
	}
	if e = writeRemote(path, localTimingPreference{Schema: 1, OwnerSID: sid, Mode: mode}); e != nil {
		return fmt.Errorf("LOCAL_TIMING_PREFERENCE_SAVE_FAILED")
	}
	b, e := coreProtectedReadBounded(path, false, true, 1024)
	if e != nil {
		return fmt.Errorf("LOCAL_TIMING_PREFERENCE_VERIFY_FAILED")
	}
	saved, e := decodeLocalTimingPreference(b, sid)
	if e != nil || saved != mode {
		return fmt.Errorf("LOCAL_TIMING_PREFERENCE_VERIFY_FAILED")
	}
	current, e := m.localDebugOwner()
	if e != nil || current != sid {
		return fmt.Errorf("LOCAL_TIMING_OWNER_CHANGED")
	}
	return nil
}
