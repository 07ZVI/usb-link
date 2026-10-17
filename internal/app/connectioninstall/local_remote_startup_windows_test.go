//go:build windows && amd64 && usblink_local_remote

package connectioninstall

import (
	"errors"
	"testing"
)

func TestLocalRemoteStartupPendingCannotAdvertiseInvitation(t *testing.T) {
	m := &RemoteManager{}
	m.localRemote.startup.record("local_firewall", errors.New("unavailable"))
	// Saved intent alone does not recreate ephemeral process authorization.
	m.SetLocalDebugIntent(true)
	if m.Enabled() {
		t.Fatal("cleanup failure enabled remote API")
	}
	_, invitation := m.Info()
	if invitation != "" || m.server != nil || m.api != nil || m.config.Enabled {
		t.Fatal("startup cleanup failure exposed listener or invitation")
	}
}
