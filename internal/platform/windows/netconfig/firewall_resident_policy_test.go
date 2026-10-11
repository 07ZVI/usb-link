package netconfig

import (
	"context"
	"encoding/json"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func residentTestSpec(t *testing.T) nativeRuleSpec {
	t.Helper()
	s, e := residentSpecs("host", usbaddress.HostGUID, "USB Link Host", `C:\Program Files\USB Link\USB-Link.exe`)
	if e != nil {
		t.Fatal(e)
	}
	return s[0]
}
func TestResidentRepairRejectsEveryChangedAnchor(t *testing.T) {
	s := residentTestSpec(t)
	for _, key := range residentAnchors {
		t.Run(key, func(t *testing.T) {
			c := expectedFirewallConstraints(s, 1)
			c[key] = []string{"S:foreign"}
			if residentRepairAllowed(c, s) == nil {
				t.Fatal("foreign scope authorized")
			}
		})
	}
}
func TestResidentRepairDefaultsOnly(t *testing.T) {
	s := residentTestSpec(t)
	c := expectedFirewallConstraints(s, 1)
	c["/Enabled"] = []string{"N:2"}
	c["/Direction"] = []string{"N:2"}
	c["MSFT_NetNetworkLayerSecurityFilter/Authentication"] = []string{"N:1"}
	if e := residentRepairAllowed(c, s); e != nil {
		t.Fatal(e)
	}
	if verifyFirewallConstraints(c, s, 1) == nil {
		t.Fatal("changed default reused")
	}
	delete(c, "/Owner")
	if residentRepairAllowed(c, s) == nil {
		t.Fatal("partial accepted")
	}
}
func TestResidentScopesFixedAndBounded(t *testing.T) {
	for _, role := range []string{"mac", "host", "ipad", "core_mac", "core_ipad"} {
		guid := usbaddress.HostGUID
		alias := "USB Link Host"
		if role == "mac" || role == "core_mac" {
			guid = "{A4611646-E050-4D25-B83E-633A5598F302}"
			alias = "USB Link"
		}
		a, e := residentSpecs(role, guid, alias, `C:\old\USB-Link.exe`)
		if e != nil {
			t.Fatal(e)
		}
		b, e := residentSpecs(role, guid, alias, `C:\new\USB-Link.exe`)
		if e != nil || len(a) != len(b) {
			t.Fatal(e)
		}
		for i := range a {
			if a[i].Name != b[i].Name || a[i].Local != b[i].Local || a[i].Remote != b[i].Remote {
				t.Fatal("scope changed")
			}
			if role == "mac" || role == "ipad" {
				if a[i].Program != "Any" || b[i].Program != "Any" {
					t.Fatal("new program widening")
				}
			}
		}
		want := 4
		if role == "mac" {
			want = 5
		}
		if role == "core_mac" {
			want = 2
		}
		if len(a) != want {
			t.Fatal(role, len(a))
		}
	}
}
func TestResidentLedgerStrictAndUpgradeOldScope(t *testing.T) {
	old, _ := residentSpecs("host", usbaddress.HostGUID, "USB Link Host", `C:\old\USB-Link.exe`)
	next, _ := residentSpecs("host", usbaddress.HostGUID, "USB Link Host", `C:\new\USB-Link.exe`)
	v := residentLedger{Version: 1, Role: "host", GUID: usbaddress.HostGUID, Phase: "prepared", ID: strings.Repeat("a", 24), Specs: next, Previous: old}
	for _, s := range old {
		v.Before = append(v.Before, residentRuleObservation{Present: true, Constraints: expectedFirewallConstraints(s, 1)})
	}
	b, _ := json.Marshal(v)
	if _, e := decodeResidentLedger(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(string(b), `"Version":1`, `"Version":1,"Version":1`, 1), strings.Replace(string(b), `"Version":1`, `"Version":1,"foreign":true`, 1), string(b) + "{}"} {
		if _, e := decodeResidentLedger([]byte(bad)); e == nil {
			t.Fatal("ambiguous parser accepted")
		}
	}
	v.Phase = "complete"
	if residentLedgerValid(v) == nil {
		t.Fatal("old program authorized as completed new program")
	}
	v.Phase = "prepared"
	v.Before[0].Constraints["MSFT_NetApplicationFilter/AppPath"] = firewallParts(`C:\foreign\USB-Link.exe`)
	if residentLedgerValid(v) == nil {
		t.Fatal("foreign program authorized")
	}
}
func TestResidentScriptExactGuardAndNoNativeMutation(t *testing.T) {
	s := residentTestSpec(t)
	v := residentLedger{Specs: []nativeRuleSpec{s}, Before: []residentRuleObservation{{Present: true, Constraints: expectedFirewallConstraints(s, 1)}}}
	script := residentScript(`C:\Windows\Temp\suhang-ipad-grouping-recovery\resident-firewall-host-v1.json`, []byte("pinned"), v, []int{0}, 23)
	for _, bad := range []string{"Invoke-CimMethod", "Set-CimInstance", "Put_", "Delete_", "-Name 'USB-Link-*'"} {
		if strings.Contains(script, bad) {
			t.Fatal(bad)
		}
	}
	if strings.Count(script, "USB-ResidentCompare (USB-ResidentSnapshot $r) $want;") != 4 {
		t.Fatal("missing initial/final double guards")
	}
	if !strings.Contains(script, "FileShare]::Read") || !strings.Contains(script, "AreAccessRulesProtected") {
		t.Fatal("receipt not pinned")
	}
	icmp, _ := residentSpecs("mac", "{A4611646-E050-4D25-B83E-633A5598F302}", "USB Link", "")
	body := residentNew(icmp[0])
	if strings.Contains(body, "-LocalPort") || strings.Contains(body, "-RemotePort") || !strings.Contains(body, "-IcmpType 8") {
		t.Fatal("ICMP ports enlarged")
	}
}

func TestResidentLegacyAdoptionRequiresCompleteOldScopeAndSource(t *testing.T) {
	old, _ := residentSpecs("host", usbaddress.HostGUID, "USB Link Host", `C:\old\USB-Link.exe`)
	next, _ := residentSpecs("host", usbaddress.HostGUID, "USB Link Host", `C:\new\USB-Link.exe`)
	obs := []residentRuleObservation{}
	for _, s := range old {
		obs = append(obs, residentRuleObservation{Present: true, Constraints: expectedFirewallConstraints(s, 1)})
	}
	calls := 0
	verify := func(p string) error {
		calls++
		if p != old[0].Program {
			t.Fatal("wrong old source")
		}
		return nil
	}
	got, e := residentRecognizeLegacySource(next, obs, "host", usbaddress.HostGUID, "USB Link Host", verify)
	if e != nil || len(got) != 4 || calls != 1 {
		t.Fatal(e, calls)
	}
	obs[0].Constraints["/Enabled"] = []string{"N:2"}
	calls = 0
	if _, e = residentRecognizeLegacySource(next, obs, "host", usbaddress.HostGUID, "USB Link Host", verify); e == nil || calls != 0 {
		t.Fatal("first adoption allowed unproved old defaults")
	}
	obs[0].Constraints = expectedFirewallConstraints(old[0], 1)
	obs[0].Constraints["/RuleGroup"] = firewallParts("foreign")
	if _, e = residentRecognizeLegacySource(next, obs, "host", usbaddress.HostGUID, "USB Link Host", verify); e == nil {
		t.Fatal("foreign marker adopted")
	}
}
func TestResidentTypedReceiptAndNoWildcards(t *testing.T) {
	s := residentTestSpec(t)
	c := expectedFirewallConstraints(s, 1)
	c["/Enabled"] = []string{"S:True"}
	if residentRepairAllowed(c, s) == nil {
		t.Fatal("untyped state")
	}
	for _, alias := range []string{"Any", "Ethernet*", "Ethernet[6]", "Ethernet?"} {
		if _, e := residentSpecs("ipad", usbaddress.HostGUID, alias, ""); e == nil {
			t.Fatal("wildcard alias", alias)
		}
	}
}
func TestResidentWorstCaseMacBatchCommandLength(t *testing.T) {
	guid := "{A4611646-E050-4D25-B83E-633A5598F302}"
	mac, _ := residentSpecs("mac", guid, "USB Link", "")
	core, _ := residentSpecs("core_mac", guid, "USB Link", `C:\Program Files\USB Link\0.8.109\USB-Link.exe`)
	plans := []ResidentPermissionPlan{}
	for role, specs := range map[string][]nativeRuleSpec{"mac": mac, "core_mac": core} {
		v := residentLedger{Role: role, GUID: guid, Phase: "prepared", Specs: specs}
		indices := []int{}
		for i, s := range specs {
			v.Before = append(v.Before, residentRuleObservation{Present: true, Constraints: expectedFirewallConstraints(s, 1)})
			indices = append(indices, i)
		}
		b, _ := json.Marshal(v)
		plans = append(plans, permissionPlanStub{residentScript(`C:\Windows\Temp\suhang-ipad-grouping-recovery\resident-firewall-`+role+`-v1.json`, b, v, indices, 23), func() error { return nil }})
	}
	network, _, e := VirtualHostMacScripts(23, guid, 1500, "0123456789abcdef01234567", []usbaddress.InterfaceProof{{Role: "host", GUID: usbaddress.HostGUID, Index: 27, LUID: 123, Created: 1}})
	if e != nil {
		t.Fatal(e)
	}
	network += PrivateProfileScript(23, guid)
	e = CompleteResidentPermissionBatch(context.Background(), network, plans, func(_ context.Context, script string) error {
		if strings.Count(script, "function USB-ResidentSnapshot") != 1 {
			t.Fatal("probe duplicated")
		}
		units := residentCommandUnits(script)
		t.Logf("MAC5+CORE2 full repair plus original virtual host network/private UTF16 conservative command units=%d", units)
		if units > 32766 {
			t.Fatal("too long", units)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestResidentCommandLimitCannotRun(t *testing.T) {
	finishes := 0
	p := permissionPlanStub{strings.Repeat("x", 40000), func() error { finishes++; return nil }}
	if CompleteResidentPermissionBatch(context.Background(), "", []ResidentPermissionPlan{p}, func(context.Context, string) error { t.Fatal("oversized command ran"); return nil }) == nil || finishes != 1 {
		t.Fatal("oversized command masked")
	}
}
