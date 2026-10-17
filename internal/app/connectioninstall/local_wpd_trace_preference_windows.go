//go:build windows && amd64 && usblink_local_remote

package connectioninstall

import (
	"fmt"
	"os"
	"path/filepath"
)

// Kept separate from the master schema so earlier installers can still read
// their own setting. This record grants no token, certificate or install consent.
func (m *RemoteManager) ReadLocalWPDTracePreference() (bool, error) {
	sid, e := m.localDebugOwner()
	if e != nil {
		return false, e
	}
	name, e := localWPDTracePreferenceName(sid)
	if e != nil {
		return false, e
	}
	b, e := coreProtectedReadBounded(filepath.Join(m.root, name), false, true, 1024)
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return false, fmt.Errorf("LOCAL_WPD_TRACE_PREFERENCE_READ_FAILED")
	}
	enabled, e := decodeLocalWPDTracePreference(b, sid)
	if e != nil {
		return false, e
	}
	current, e := m.localDebugOwner()
	if e != nil || current != sid {
		return false, fmt.Errorf("LOCAL_WPD_TRACE_OWNER_CHANGED")
	}
	return enabled, nil
}
func (m *RemoteManager) SaveLocalWPDTracePreference(enabled bool) error {
	sid, e := m.localDebugOwner()
	if e != nil {
		return e
	}
	if _, e = coreProtectedRead(m.root, true, false); e != nil {
		return fmt.Errorf("LOCAL_WPD_TRACE_PREFERENCE_PROTECTION_FAILED")
	}
	name, e := localWPDTracePreferenceName(sid)
	if e != nil {
		return e
	}
	path := filepath.Join(m.root, name)
	if _, e = coreProtectedReadBounded(path, false, true, 1024); e != nil && !os.IsNotExist(e) {
		return fmt.Errorf("LOCAL_WPD_TRACE_PREFERENCE_PROTECTION_FAILED")
	}
	if e = writeRemote(path, localWPDTracePreference{Schema: 1, OwnerSID: sid, Enabled: &enabled}); e != nil {
		return fmt.Errorf("LOCAL_WPD_TRACE_PREFERENCE_SAVE_FAILED")
	}
	b, e := coreProtectedReadBounded(path, false, true, 1024)
	if e != nil {
		return fmt.Errorf("LOCAL_WPD_TRACE_PREFERENCE_VERIFY_FAILED")
	}
	saved, e := decodeLocalWPDTracePreference(b, sid)
	if e != nil || saved != enabled {
		return fmt.Errorf("LOCAL_WPD_TRACE_PREFERENCE_VERIFY_FAILED")
	}
	current, e := m.localDebugOwner()
	if e != nil || current != sid {
		return fmt.Errorf("LOCAL_WPD_TRACE_OWNER_CHANGED")
	}
	return nil
}
