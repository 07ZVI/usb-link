//go:build windows && amd64 && !usblink_local_remote

package connectioninstall

type localRemoteState struct{}

const localRemoteBuild = false

func (m *RemoteManager) initializeLocalRemote() error   { return nil }
func (m *RemoteManager) closeLocalRemoteConsentLocked() {}
func (m *RemoteManager) localRemoteListenerStatus() any { return nil }

func (m *RemoteManager) startLocalRemoteWatcher() {}
func (m *RemoteManager) openLocalRemote() error   { return errRemoteMaintenanceRemoved }
func (m *RemoteManager) enableLocalRemote(enabled bool) error {
	if enabled {
		return errRemoteMaintenanceRemoved
	}
	return m.disablePublicRemote()
}
func (m *RemoteManager) localRemoteEnabled() bool { return false }
func (m *RemoteManager) localRemoteInfo() (string, string) {
	return "Remote maintenance is not available in the public build", ""
}

func (m *RemoteManager) localRemoteFailureStatus() any { return nil }

func (m *RemoteManager) lockRemoteStatus() bool            { m.mu.Lock(); return true }
func (m *RemoteManager) localRemotePreparingSnapshot() any { return nil }

func (m *RemoteManager) deferLocalRemoteStartupCleanup(error) bool { return false }
