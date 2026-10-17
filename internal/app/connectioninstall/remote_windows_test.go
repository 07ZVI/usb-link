//go:build windows && amd64

package connectioninstall

import (
	"encoding/json"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/app/remoteupdate"
	"testing"
)

func TestLegacyRemoteConfigNeverGrantsAutomaticInstallation(t *testing.T) {
	var c remoteConfig
	if e := json.Unmarshal([]byte(`{"enabled":true,"token":"legacy"}`), &c); e != nil || c.AutoUpgrade {
		t.Fatal(c, e)
	}
}

func TestPublicBuildRejectsRemoteMaintenanceEvenWithOldConsent(t *testing.T) {
	if localRemoteBuild {
		t.Skip("public-build isolation test")
	}
	m := &RemoteManager{root: t.TempDir(), config: remoteConfig{Enabled: true, AutoUpgrade: true, Token: "old"}}
	m.rawUSB.Store(true)
	if m.Enabled() || m.AutoUpgrade() {
		t.Fatal("old consent restored remote access")
	}
	for _, err := range []error{m.Enable(true), m.SetAutoUpgrade(true), m.open()} {
		if err != errRemoteMaintenanceRemoved {
			t.Fatalf("remote entry not removed: %v", err)
		}
	}
	if handler, config, err := m.RecoveryAPI(); handler != nil || config != nil || err != errRemoteMaintenanceRemoved {
		t.Fatal("raw USB remote API exposed")
	}
	if invitation, err := m.RecoveryInvitation(); len(invitation) != 0 || err != errRemoteMaintenanceRemoved {
		t.Fatal("raw invitation exposed")
	}
	if _, invitation := m.Info(); invitation != "" {
		t.Fatal("network invitation exposed")
	}
	if _, err := m.stage(remoteupdate.Manifest{}, nil); err != errRemoteMaintenanceRemoved {
		t.Fatal("remote staging accepted")
	}
	if err := m.apply(nil, "old-job"); err != errRemoteMaintenanceRemoved {
		t.Fatal("remote apply accepted")
	}
	if err := m.Enable(false); err != nil {
		t.Fatal(err)
	}
	var saved remoteConfig
	if err := readRemote(filepath.Join(m.root, "config.json"), &saved); err != nil || saved.Enabled || saved.AutoUpgrade || saved.Token != "" || len(saved.Key) != 0 {
		t.Fatal("old credential retained", err)
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
