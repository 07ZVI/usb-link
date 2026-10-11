//go:build windows && amd64

package connectioninstall

import (
	"encoding/json"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyRemoteConfigNeverGrantsAutomaticInstallation(t *testing.T) {
	var c remoteConfig
	if e := json.Unmarshal([]byte(`{"enabled":true,"token":"legacy"}`), &c); e != nil || c.AutoUpgrade {
		t.Fatal(c, e)
	}
}

func TestLocalAutoUpgradePersistenceAndFailure(t *testing.T) {
	m := &RemoteManager{root: t.TempDir(), config: remoteConfig{Enabled: true}}
	err := m.SetAutoUpgrade(true)
	if !windows.GetCurrentProcessToken().IsElevated() {
		if err == nil || m.AutoUpgrade() {
			t.Fatal("unelevated authorization allowed")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	var c remoteConfig
	if e := readRemote(filepath.Join(m.root, "config.json"), &c); e != nil || !c.AutoUpgrade {
		t.Fatal(c, e)
	}
	if e := m.SetAutoUpgrade(false); e != nil || m.AutoUpgrade() {
		t.Fatal(e)
	}
	if e := readRemote(filepath.Join(m.root, "config.json"), &c); e != nil || c.AutoUpgrade {
		t.Fatal(c, e)
	}
	m.config.Enabled = false
	if e := m.SetAutoUpgrade(true); e == nil {
		t.Fatal("debug off allowed automatic updates")
	}
	m.config.Enabled = true
	m.root = filepath.Join(m.root, "missing-parent")
	if e := m.SetAutoUpgrade(true); e == nil || m.AutoUpgrade() {
		t.Fatal("failed write published authorization")
	}
}

func TestMissingRemoteConfigIsFirstLaunch(t *testing.T) {
	var c remoteConfig
	if e := readRemote(filepath.Join(t.TempDir(), "config.json"), &c); !os.IsNotExist(e) {
		t.Fatalf("missing config must retain its not-exist classification: %v", e)
	}
}
func TestMaintenanceACLAcceptsEquivalentAndRejectsBroaderAccess(t *testing.T) {
	wanted, e := windows.SecurityDescriptorFromString(remoteACL)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		value    string
		accepted bool
	}{
		{remoteACL, true},
		{"D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)", true},
		{installACL, false},
		{"D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", false},
		{"D:P(A;OICI;FA;;;SY)", false},
	} {
		actual, e := windows.SecurityDescriptorFromString(tc.value)
		if e != nil {
			t.Fatal(e)
		}
		if sameACL(actual, wanted) != tc.accepted {
			t.Errorf("unexpected permission result for %s", tc.value)
		}
	}
}
