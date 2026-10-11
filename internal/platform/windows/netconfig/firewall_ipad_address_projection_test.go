package netconfig

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func ipadAddressFixture() IPadAddressProjectionReport {
	v := ipadAddressReport()
	v.Status = "observed"
	for i := range v.Rows {
		p := IPadAddressProjection{Status: "observed", RuleCount: 1, FilterCount: 1, MarkersMatch: true, ProgramMatch: true, InterfaceMatch: true, Local: IPadAddressShape{Kind: "null"}, Remote: ipadAddressShape([]string{"Any"}, "array", "Any")}
		v.Rows[i].Public = p
		v.Rows[i].Native = p
	}
	return v
}
func TestIPadAddressProjectionPreservesNullWithoutAnyAuthority(t *testing.T) {
	v := ipadAddressFixture()
	b, _ := json.Marshal(v)
	out, e := DecodeIPadAddressProjection(b)
	if e != nil || out.Rows[0].Native.Local.Kind != "null" || out.Rows[0].Native.Local.IsAny || out.Rows[0].Native.Local.ExpectedExact {
		t.Fatal(out, e)
	}
	for _, private := range []string{"GUID", "LUID", "exe", "path", "rule_name", "local_address", "remote_address", "verified", "ready"} {
		if strings.Contains(string(b), private) {
			t.Fatal(private)
		}
	}
	if ipadAddressShape([]string{"Any", "Any"}, "array", "Any").ExpectedExact || ipadAddressShape([]string{"Any"}, "array", "10.6.9.1").ExpectedExact {
		t.Fatal("Any broadened exact local")
	}
	if !ipadAddressShape([]string{"10.6.9.1"}, "array", "10.6.9.1").ExpectedExact {
		t.Fatal("exact local mismatch")
	}
}
func TestIPadAddressProjectionStrictShapeRejectsAmbiguityAndAuthority(t *testing.T) {
	v := ipadAddressFixture()
	b, _ := json.Marshal(v)
	bad := []string{
		string(b) + "{}",
		strings.Replace(string(b), `"duration_ms":0`, `"duration_ms":12001`, 1),
		strings.Replace(string(b), `"read_only":true`, `"read_only":true,"read_only":true`, 1),
		strings.Replace(string(b), `"read_only":true,`, "", 1),
		strings.Replace(string(b), `"rule_count":1`, `"rule_count":3`, 1),
		strings.Replace(string(b), `"selector_index":1`, `"selector_index":0`, 1),
		strings.Replace(string(b), `"kind":"null","count":0,"is_any":false`, `"kind":"null","count":0,"is_any":true`, 1),
		strings.Replace(string(b), `"kind":"null","count":0`, `"kind":"null"`, 1),
		strings.Replace(string(b), `"status":"observed"`, `"status":"ready"`, 1),
		strings.Replace(string(b), `"schema":1`, `"schema":1,"path":"PRIVATE"`, 1),
	}
	for i, s := range bad {
		if _, e := DecodeIPadAddressProjection([]byte(s)); e == nil {
			t.Fatal("accepted invalid", i)
		}
	}
}
func TestIPadAddressProjectionHasOnlyFourCompiledSelectorsAndReads(t *testing.T) {
	s, e := residentSpecs("core_ipad", "{11111111-2222-3333-4444-555555555555}", "Ethernet 6", `C:\Program Files\USB Link\0.8.116\USB-Link.exe`)
	if e != nil || len(s) != 4 {
		t.Fatal(e)
	}
	for i := range s {
		want := "10.6.9.1"
		if i >= 2 {
			want = "Any"
		}
		if s[i].Local != want {
			t.Fatal(i, s[i])
		}
	}
	script := ipadAddressPublicScript(s)
	for _, required := range []string{"Get-NetFirewallRule -PolicyStore PersistentStore", "Get-NetFirewallAddressFilter -AssociatedNetFirewallRule", "$rs.Count -ne 1", "$af.Count -ne 1", "selector_index=$i", "$json.Length -gt 8192", IPadAddressProjectionPrefix} {
		if !strings.Contains(script, required) {
			t.Fatal(required)
		}
	}
	for _, bad := range []string{"New-Net", "Set-Net", "Remove-Net", "Invoke-", "Delete_", "Put_"} {
		if strings.Contains(script, bad) {
			t.Fatal("mutation", bad)
		}
	}
	source, e := os.ReadFile("firewall_ipad_address_projection_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"cimSet(", "cimPut(", "cimDelete(", "writeResidentLedger", "clearResidentLedger", "PrepareResidentCoreFirewall(", "RunContext("} {
		if strings.Contains(string(source), bad) {
			t.Fatal("native write", bad)
		}
	}
	for _, required := range []string{"12*time.Second", "CompareAndSwap(false, true)", `beginNetworkTiming("legacy_network_script")`, `beginNetworkTiming("ipad_address_diagnostic_script")`, "detail.Field != \"MSFT_NetAddressFilter/LocalAddress\"", "complete() != nil", "verify(ctx) != nil"} {
		if !strings.Contains(strings.ReplaceAll(string(source), " ", ""), strings.ReplaceAll(required, " ", "")) {
			t.Fatal("bound missing", required)
		}
	}
}
