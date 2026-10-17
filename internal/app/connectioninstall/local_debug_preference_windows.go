//go:build windows && amd64 && usblink_local_remote

package connectioninstall

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (m *RemoteManager) localDebugOwner() (string, error) {
	b, e := CurrentCoreBinding()
	if e != nil || !validPreparedUserSID(b.OwnerSID) || !strings.EqualFold(b.Executable, m.installed) || VerifyCoreExecutable(b.Executable) != nil || m.recoveryOnly || m.closing.Load() {
		return "", fmt.Errorf("LOCAL_DEBUG_OWNER_UNAVAILABLE")
	}
	return b.OwnerSID, nil
}

func (m *RemoteManager) ReadLocalDebugPreference() (bool, error) {
	sid, e := m.localDebugOwner()
	if e != nil {
		return false, e
	}
	name, e := localDebugPreferenceName(sid)
	if e != nil {
		return false, e
	}
	b, e := coreProtectedReadBounded(filepath.Join(m.root, name), false, true, 1024)
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return false, fmt.Errorf("LOCAL_DEBUG_PREFERENCE_READ_FAILED")
	}
	enabled, e := decodeLocalDebugPreference(b, sid)
	if e != nil {
		return false, e
	}
	current, e := m.localDebugOwner()
	if e != nil || current != sid {
		return false, fmt.Errorf("LOCAL_DEBUG_OWNER_CHANGED")
	}
	return enabled, nil
}

func (m *RemoteManager) SaveLocalDebugPreference(enabled bool) error {
	sid, e := m.localDebugOwner()
	if e != nil {
		return e
	}
	if _, e = coreProtectedRead(m.root, true, false); e != nil {
		return fmt.Errorf("LOCAL_DEBUG_PREFERENCE_PROTECTION_FAILED")
	}
	name, e := localDebugPreferenceName(sid)
	if e != nil {
		return e
	}
	path := filepath.Join(m.root, name)
	if _, e = coreProtectedReadBounded(path, false, true, 1024); e != nil && !os.IsNotExist(e) {
		return fmt.Errorf("LOCAL_DEBUG_PREFERENCE_PROTECTION_FAILED")
	}
	if e = writeRemote(path, localDebugPreference{Schema: 1, OwnerSID: sid, Enabled: &enabled}); e != nil {
		return fmt.Errorf("LOCAL_DEBUG_PREFERENCE_SAVE_FAILED")
	}
	b, e := coreProtectedReadBounded(path, false, true, 1024)
	if e != nil {
		return fmt.Errorf("LOCAL_DEBUG_PREFERENCE_VERIFY_FAILED")
	}
	saved, e := decodeLocalDebugPreference(b, sid)
	if e != nil || saved != enabled {
		return fmt.Errorf("LOCAL_DEBUG_PREFERENCE_VERIFY_FAILED")
	}
	current, e := m.localDebugOwner()
	if e != nil || current != sid {
		return fmt.Errorf("LOCAL_DEBUG_OWNER_CHANGED")
	}
	return nil
}

// Closing intent revokes admission before any slow firewall operation can finish.
func (m *RemoteManager) SetLocalDebugIntent(enabled bool) error {
	m.localRemote.admitted.Store(false)
	return m.localRemote.consent.selectIntent(enabled, m.localRemote.desired.Store, func() error {
		return writeRemote(filepath.Join(m.root, localInstallConsentFile), localInstallConsentReceipt{})
	})
}

func (m *RemoteManager) LocalDebugTransportStatus() (bool, bool, string) {
	if !m.localRemote.desired.Load() || m.closing.Load() {
		return false, false, "off"
	}
	if !m.mu.TryLock() {
		return false, false, "preparing"
	}
	defer m.mu.Unlock()
	if m.lastError != "" {
		return m.config.Enabled, false, "failed"
	}
	if !m.config.Enabled || !m.localRemote.admitted.Load() {
		return false, false, "off"
	}
	if m.server == nil {
		return true, false, "waiting_usb"
	}
	return true, true, "ready"
}

func (m *RemoteManager) localRemotePreparingSnapshot() any {
	return map[string]any{"version": m.version, "enabled": false, "listening": false, "preparing": true}
}
func (m *RemoteManager) lockRemoteStatus() bool { return m.mu.TryLock() }
