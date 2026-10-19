//go:build windows && amd64 && usblink_local_remote

package connectioninstall

import (
	"fmt"
	"os"
	"path/filepath"

	"suhang/usbnet/internal/transport/ncm"
)

// Kept separate from the master schema so earlier installers can still read
// their own setting. This record grants no token, certificate or install consent.
func (m *RemoteManager) ReadLocalMacMTUCapPreference() (string, error) {
	sid, e := m.localDebugOwner()
	if e != nil {
		return "", e
	}
	name, e := localMacMTUCapPreferenceName(sid)
	if e != nil {
		return "", e
	}
	b, e := coreProtectedReadBounded(filepath.Join(m.root, name), false, true, 1024)
	if os.IsNotExist(e) {
		return ncm.MTUCapAuto.String(), nil
	}
	if e != nil {
		return "", fmt.Errorf("LOCAL_MAC_MTU_CAP_PREFERENCE_READ_FAILED")
	}
	value, e := decodeLocalMacMTUCapPreference(b, sid)
	if e != nil {
		return "", e
	}
	current, e := m.localDebugOwner()
	if e != nil || current != sid {
		return "", fmt.Errorf("LOCAL_MAC_MTU_CAP_OWNER_CHANGED")
	}
	return value, nil
}
func (m *RemoteManager) SaveLocalMacMTUCapPreference(value string) error {
	if _, e := ncm.ParseMTUCap(value); e != nil {
		return e
	}
	sid, e := m.localDebugOwner()
	if e != nil {
		return e
	}
	if _, e = coreProtectedRead(m.root, true, false); e != nil {
		return fmt.Errorf("LOCAL_MAC_MTU_CAP_PREFERENCE_PROTECTION_FAILED")
	}
	name, e := localMacMTUCapPreferenceName(sid)
	if e != nil {
		return e
	}
	path := filepath.Join(m.root, name)
	if _, e = coreProtectedReadBounded(path, false, true, 1024); e != nil && !os.IsNotExist(e) {
		return fmt.Errorf("LOCAL_MAC_MTU_CAP_PREFERENCE_PROTECTION_FAILED")
	}
	if e = writeRemote(path, localMacMTUCapPreference{Schema: 1, OwnerSID: sid, Cap: value}); e != nil {
		return fmt.Errorf("LOCAL_MAC_MTU_CAP_PREFERENCE_SAVE_FAILED")
	}
	b, e := coreProtectedReadBounded(path, false, true, 1024)
	if e != nil {
		return fmt.Errorf("LOCAL_MAC_MTU_CAP_PREFERENCE_VERIFY_FAILED")
	}
	saved, e := decodeLocalMacMTUCapPreference(b, sid)
	if e != nil || saved != value {
		return fmt.Errorf("LOCAL_MAC_MTU_CAP_PREFERENCE_VERIFY_FAILED")
	}
	current, e := m.localDebugOwner()
	if e != nil || current != sid {
		return fmt.Errorf("LOCAL_MAC_MTU_CAP_OWNER_CHANGED")
	}
	return nil
}
