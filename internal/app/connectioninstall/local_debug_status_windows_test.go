//go:build windows && amd64 && usblink_local_remote

package connectioninstall

import "testing"

func TestLocalDebugStatusDoesNotWaitForFirewallLock(t *testing.T) {
	m := &RemoteManager{version: "test", root: t.TempDir()}
	m.localRemote.desired.Store(true)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, snapshot := range []any{m.Snapshot(), m.ListenerStatus()} {
		s := snapshot.(map[string]any)
		if s["preparing"] != true || s["enabled"] != false || s["listening"] != false {
			t.Fatal(s)
		}
	}
	if m.Enabled() {
		t.Fatal("locked preparation advertised authorization")
	}
	if _, token := m.Info(); token != "" {
		t.Fatal("exposed invitation during preparation")
	}
	enabled, ready, phase := m.LocalDebugTransportStatus()
	if enabled || ready || phase != "preparing" {
		t.Fatal(enabled, ready, phase)
	}
	if err := m.SetLocalDebugIntent(false); err != nil {
		t.Fatal(err)
	}
	if m.localRemoteGenerationActive(nil, 0, "", nil) {
		t.Fatal("revoked admission remained active")
	}
}
