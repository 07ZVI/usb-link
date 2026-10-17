//go:build usblink_local_remote

package netconfig

import (
	"errors"
	"maps"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func localMaintenanceFixture(t *testing.T) (nativeRuleSpec, firewallConstraints) {
	t.Helper()
	s, err := localMaintenanceSpec(`C:\owned\USB-Link.exe`, "USB Link Host")
	if err != nil {
		t.Fatal(err)
	}
	_, got := firewallPolicyFixture()
	got["/InstanceID"] = []string{"S:" + localMaintenanceRule}
	got["/DisplayName"] = []string{"S:USB Link local USB push"}
	got["/ElementName"] = []string{"S:USB Link local USB push"}
	got["/RuleGroup"] = []string{"S:USB-Link-Local-Push-v2"}
	got["/Description"] = []string{"S:" + s.Description}
	got["MSFT_NetProtocolPortFilter/LocalPort"] = []string{"S:47775"}
	return s, got
}

func TestLocalMaintenanceOnlyExactUSBPushScope(t *testing.T) {
	s, got := localMaintenanceFixture(t)
	if s.Ports != "47775" || s.Protocol != 6 || s.Local != "10.6.9.1" || s.Remote != "10.6.9.2" || s.Alias != "USB Link Host" || s.Program == "Any" {
		t.Fatal("local push widened scope")
	}
	actual, err := localMaintenanceCleanupSpec(got)
	if err != nil || actual != s {
		t.Fatalf("valid full rule rejected: %v", err)
	}
	for field := range got {
		changed := maps.Clone(got)
		delete(changed, field)
		if _, err := localMaintenanceCleanupSpec(changed); err == nil {
			t.Fatalf("missing %s accepted", field)
		}
	}
	for field, value := range map[string]string{
		"MSFT_NetInterfaceFilter/InterfaceAlias": "S:Foreign network",
		"MSFT_NetAddressFilter/RemoteAddress":    "S:Any",
		"MSFT_NetAddressFilter/LocalAddress":     "S:Any",
		"MSFT_NetProtocolPortFilter/LocalPort":   "S:445",
		"/RuleGroup":                             "S:Other", "/Description": "S:Other", "/Enabled": "N:0",
	} {
		changed := maps.Clone(got)
		changed[field] = []string{value}
		if _, err := localMaintenanceCleanupSpec(changed); err == nil {
			t.Fatalf("changed %s accepted", field)
		}
	}
	got["/Enabled"] = []string{"N:2"}
	if _, err := localMaintenanceCleanupSpec(got); err != nil {
		t.Fatal("complete disabled rule should remain cleanable", err)
	}
}

func TestLocalMaintenanceCleanupRetainsUnknownOwnerOrChangedRule(t *testing.T) {
	s, got := localMaintenanceFixture(t)
	removed := false
	remove := func(nativeRuleSpec, string) error { removed = true; return nil }
	read := func(nativeRuleSpec) (firewallConstraints, error) { return got, nil }
	if err := executeNativeRuleCleanup([]nativeRuleSpec{s}, read, func() error { return errors.New("unverified executable") }, remove); err == nil || removed {
		t.Fatal("deleted unverified owner")
	}
	reads := 0
	read = func(nativeRuleSpec) (firewallConstraints, error) {
		reads++
		if reads > 2 {
			changed := maps.Clone(got)
			changed["/Owner"] = []string{"S:foreign"}
			return changed, nil
		}
		return got, nil
	}
	if err := executeNativeRuleCleanup([]nativeRuleSpec{s}, read, func() error { return nil }, remove); err == nil || removed {
		t.Fatal("deleted changing rule")
	}
}

func TestLocalMaintenanceCmdletsAreFixedAndGuardFullBaseline(t *testing.T) {
	s, got := localMaintenanceFixture(t)
	host := usbaddress.InterfaceProof{Role: "host", GUID: usbaddress.HostGUID, Index: 23, LUID: 123, Created: 456}
	script, err := localMaintenanceCreationScript(host, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"-Enabled False", "-LocalAddress '10.6.9.1'", "-RemoteAddress '10.6.9.2'", "-Protocol TCP -LocalPort 47775", "USB_LOCAL_PUSH_NAME_OCCUPIED", "-Program 'C:\\owned\\USB-Link.exe'"} {
		if !strings.Contains(script, text) {
			t.Fatalf("missing fixed gate %q", text)
		}
	}
	if strings.Contains(script, "-Enabled True") || strings.Contains(script, "Set-NetFirewallRule") {
		t.Fatal("creation enabled a rule")
	}
	wrong := s
	wrong.Remote = "Any"
	if _, err := localMaintenanceCreationScript(host, wrong); err == nil {
		t.Fatal("accepted wider peer")
	}
	quoted, err := localMaintenanceSpec(`C:\owned\O'Brien\USB-Link.exe`, usbaddress.HostName)
	if err != nil {
		t.Fatal(err)
	}
	quotedScript, err := localMaintenanceCreationScript(host, quoted)
	if err != nil || !strings.Contains(quotedScript, `-Program 'C:\owned\O''Brien\USB-Link.exe'`) {
		t.Fatal("unsafe executable quoting")
	}
	got["/Enabled"] = []string{"N:2"}
	script, err = localMaintenanceEnableScript(host, s, got, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(script, "USB-ResidentCompare (USB-ResidentSnapshot $r) $want;") != 2 || strings.LastIndex(script, "USB-ResidentCompare (USB-ResidentSnapshot $r) $want;") > strings.Index(script, "$fr[0]|Set-NetFirewallRule") || len(script) > 24000 {
		t.Fatal("missing bounded full baseline comparisons")
	}
	if _, err = localMaintenanceEnableScript(host, s, got, false); err == nil {
		t.Fatal("disabled baseline authorized disable of another state")
	}
	delete(got, "/Owner")
	if _, err = localMaintenanceEnableScript(host, s, got, true); err == nil {
		t.Fatal("incomplete baseline authorized enable")
	}
}

func TestLocalMaintenanceEnableRequiresTwoDisabledReadsAndTwoEnabledReads(t *testing.T) {
	for failRead := 0; failRead <= 4; failRead++ {
		s, got := localMaintenanceFixture(t)
		got["/Enabled"] = []string{"N:2"}
		reads, enabled := 0, false
		read := func() (firewallConstraints, error) {
			reads++
			if reads == failRead {
				return nil, errors.New("read failed")
			}
			return got, nil
		}
		hash, err := completeLocalMaintenanceRule(s, read, func() error { return nil }, func() error {
			if reads != 2 {
				t.Fatal("enabled before two complete readbacks")
			}
			enabled = true
			got["/Enabled"] = []string{"N:1"}
			return nil
		})
		if failRead == 0 {
			if err != nil || hash == "" || reads != 4 || !enabled {
				t.Fatal("complete transaction rejected", err)
			}
		} else {
			if err == nil || hash != "" {
				t.Fatal("failed transaction published baseline")
			}
			if failRead <= 2 && enabled {
				t.Fatal("failed disabled read still enabled rule")
			}
		}
	}
}

func TestLocalMaintenanceLegacyCompleteRulesRemainExactlyCleanable(t *testing.T) {
	s, got := localMaintenanceFixture(t)
	s.Name, s.Group = legacyLocalMaintenanceRule, "USB-Link-Local-Push-v1"
	s.Description = strings.Replace(s.Description, "local push v2;", "local push;", 1)
	got["/InstanceID"] = []string{"S:" + s.Name}
	got["/RuleGroup"] = []string{"S:" + s.Group}
	got["/Description"] = []string{"S:" + s.Description}
	actual, err := localMaintenanceCleanupSpec(got)
	if err != nil || actual != s {
		t.Fatal("complete legacy rule rejected", err)
	}
	script, err := localMaintenanceRemovalScript(s, got)
	if err != nil || strings.Count(script, "USB-ResidentCompare (USB-ResidentSnapshot $r) $want;") != 2 || !strings.Contains(script, "$fr[0]|Remove-NetFirewallRule") {
		t.Fatal("legacy removal lacks exact baseline", err)
	}
	got["MSFT_NetAddressFilter/RemoteAddress"] = []string{"S:Any"}
	if _, err = localMaintenanceRemovalScript(s, got); err == nil {
		t.Fatal("unknown legacy scope authorized deletion")
	}
}

func TestLocalMaintenanceUnknownLegacyRetentionRequiresTwoDisabledReads(t *testing.T) {
	for _, name := range []string{legacyLocalMaintenanceRule, localMaintenanceRule, "foreign"} {
		for _, first := range []int32{0, 1, 2, 3} {
			for _, second := range []int32{0, 1, 2, 3} {
				want := name == legacyLocalMaintenanceRule && first == 2 && second == 2
				if localMaintenanceRetainDisabledLegacy(name, first, second) != want {
					t.Fatal("unsafe legacy retention gate")
				}
			}
		}
	}
}
