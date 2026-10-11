package netconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestMacFirstFailureCarriesOnlyActualFixedConstraintField(t *testing.T) {
	for _, f := range []struct{ class, property, want string }{
		{"", "Description", "MSFT_NetFirewallRule/Description"},
		{"MSFT_NetApplicationFilter", "AppPath", "MSFT_NetApplicationFilter/AppPath"},
		{"MSFT_NetServiceFilter", "_association", "MSFT_NetServiceFilter/_association"},
	} {
		var first FirstMacStartupFailure
		cause := firewallReadFailure(f.class, f.property, errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_NULL"))
		b, ok := first.Capture("mac_resident_mac_plan", fmt.Errorf("private provider source: %w", cause))
		row, e := DecodeNativeStepFailureMessage(b)
		if !ok || e != nil || row.CauseField != f.want || row.CauseCode != "USB_NATIVE_FIREWALL_CONSTRAINT_NULL" || strings.Contains(string(b), "private") {
			t.Fatal(string(b), row, e)
		}
		for _, bad := range []string{
			strings.Replace(string(b), `"cause_field":"`+f.want+`"`, `"cause_field":"private SOURCE"`, 1),
			strings.Replace(string(b), `"cause_field":"`+f.want+`"`, `"cause_field":null`, 1),
			strings.Replace(string(b), `"cause_field":"`+f.want+`"`, `"cause_field":"`+f.want+`","cause_field":"`+f.want+`"`, 1),
		} {
			if _, e := DecodeNativeStepFailureMessage([]byte(bad)); e == nil {
				t.Fatal("unsafe field accepted", bad)
			}
		}
		row.CauseCode = ""
		b, _ = json.Marshal(row)
		if _, e := DecodeNativeStepFailureMessage(b); e == nil {
			t.Fatal("field without actual finite cause accepted")
		}
	}
}

func TestMacForeignAnchorFailureCarriesActualCompiledField(t *testing.T) {
	s := residentMacCompiledSpecs()[0]
	got := expectedFirewallConstraints(s, 1)
	got["MSFT_NetProtocolPortFilter/IcmpType"] = []string{"S:8:*"}
	err := residentRepairAllowed(got, s)
	if err == nil {
		t.Fatal("diagnostic must not normalize foreign ICMP")
	}
	var first FirstMacStartupFailure
	b, ok := first.Capture("mac_resident_mac_plan", err)
	row, e := DecodeNativeStepFailureMessage(b)
	if !ok || e != nil || row.CauseCode != "USB_RESIDENT_FOREIGN_SCOPE" || row.CauseField != "MSFT_NetProtocolPortFilter/IcmpType" {
		t.Fatal(row, e, ok)
	}
}
