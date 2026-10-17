//go:build windows && amd64 && usblink_local_remote

package connectioninstall

import (
	"fmt"
	"os"
	"path/filepath"
)

// Kept separate from the master schema so earlier installers can still read
// their own setting. This record grants no token, certificate or install consent.
func (m *RemoteManager) ReadLocalAMDSHoldPreference() (bool, error) {
	sid, e := m.localDebugOwner()
	if e != nil {
		return false, e
	}
	name, e := localAMDSHoldPreferenceName(sid)
	if e != nil {
		return false, e
	}
	b, e := coreProtectedReadBounded(filepath.Join(m.root, name), false, true, 1024)
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return false, fmt.Errorf("LOCAL_AMDS_HOLD_PREFERENCE_READ_FAILED")
	}
	enabled, e := decodeLocalAMDSHoldPreference(b, sid)
	if e != nil {
		return false, e
	}
	current, e := m.localDebugOwner()
	if e != nil || current != sid {
		return false, fmt.Errorf("LOCAL_AMDS_HOLD_OWNER_CHANGED")
	}
	return enabled, nil
}
func (m *RemoteManager) SaveLocalAMDSHoldPreference(enabled bool) error {
	sid, e := m.localDebugOwner()
	if e != nil {
		return e
	}
	if _, e = coreProtectedRead(m.root, true, false); e != nil {
		return fmt.Errorf("LOCAL_AMDS_HOLD_PREFERENCE_PROTECTION_FAILED")
	}
	name, e := localAMDSHoldPreferenceName(sid)
	if e != nil {
		return e
	}
	path := filepath.Join(m.root, name)
	if _, e = coreProtectedReadBounded(path, false, true, 1024); e != nil && !os.IsNotExist(e) {
		return fmt.Errorf("LOCAL_AMDS_HOLD_PREFERENCE_PROTECTION_FAILED")
	}
	if e = writeRemote(path, localAMDSHoldPreference{Schema: 1, OwnerSID: sid, Enabled: &enabled}); e != nil {
		return fmt.Errorf("LOCAL_AMDS_HOLD_PREFERENCE_SAVE_FAILED")
	}
	b, e := coreProtectedReadBounded(path, false, true, 1024)
	if e != nil {
		return fmt.Errorf("LOCAL_AMDS_HOLD_PREFERENCE_VERIFY_FAILED")
	}
	saved, e := decodeLocalAMDSHoldPreference(b, sid)
	if e != nil || saved != enabled {
		return fmt.Errorf("LOCAL_AMDS_HOLD_PREFERENCE_VERIFY_FAILED")
	}
	current, e := m.localDebugOwner()
	if e != nil || current != sid {
		return fmt.Errorf("LOCAL_AMDS_HOLD_OWNER_CHANGED")
	}
	return nil
}
