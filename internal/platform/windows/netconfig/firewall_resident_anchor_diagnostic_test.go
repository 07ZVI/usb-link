package netconfig

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestResidentRepairFailureIdentifiesActualAnchorWithoutValues(t *testing.T) {
	s := residentMacCompiledSpecs()[0]
	for _, key := range residentAnchors {
		c := expectedFirewallConstraints(s, 1)
		c[key] = []string{"S:PRIVATE_FOREIGN_VALUE"}
		e := residentRepairAllowed(c, s)
		d := ResidentFirewallErrorDetails(e)
		class, field, _ := strings.Cut(key, "/")
		if class == "" {
			class = firewallRuleDiagnosticClass
		}
		if e == nil || d.Field != class+"/"+field || (d.Code != "USB_RESIDENT_FOREIGN_SCOPE" && d.Code != "USB_RESIDENT_CONSTRAINT_TYPE_UNKNOWN") || strings.Contains(e.Error(), "PRIVATE") {
			t.Fatal(key, d)
		}
	}
	c := expectedFirewallConstraints(s, 1)
	c["MSFT_NetProtocolPortFilter/IcmpType"] = []string{"S:8:*"}
	d := ResidentFirewallErrorDetails(residentRepairAllowed(c, s))
	if d.Code != "USB_RESIDENT_FOREIGN_SCOPE" || d.Field != "MSFT_NetProtocolPortFilter/IcmpType" || verifyResidentFirewallConstraints(c, s, 1) == nil {
		t.Fatal("unproved ICMP shape was accepted", d)
	}
	c = expectedFirewallConstraints(s, 1)
	c["MSFT_NetProtocolPortFilter/DynamicTransport"] = []string{"N:999"}
	d = ResidentFirewallErrorDetails(residentRepairAllowed(c, s))
	if d.Code != "USB_RESIDENT_CONSTRAINT_TYPE_UNKNOWN" || d.Field != "MSFT_NetProtocolPortFilter/DynamicTransport" {
		t.Fatal(d)
	}
	if d = ResidentFirewallErrorDetails(residentConstraintFailure("private/PRIVATE_FOREIGN_VALUE", errors.New("USB_RESIDENT_FOREIGN_SCOPE"))); d.Field != "" {
		t.Fatal("arbitrary key exported")
	}
}

func TestResidentMacAnchorProjectionFixedReadOnlyAndBounded(t *testing.T) {
	s := ResidentMacAnchorProjectionScript()
	for _, spec := range residentMacCompiledSpecs() {
		if strings.Count(s, residentQuote(spec.Name)) != 1 {
			t.Fatal("selector changed", spec.Name)
		}
	}
	for _, write := range []string{"Set-Net", "New-Net", "Remove-Net", "Enable-Net", "Disable-Net", "Set-Cim", "New-Cim", "Remove-Cim", "Invoke-Cim", "Put_", "Out-File", "Set-Content", "Add-Content", "USB-ResidentPin"} {
		if strings.Contains(s, write) {
			t.Fatal("mutation or file pin", write)
		}
	}
	for _, key := range residentAnchors {
		class, field, _ := strings.Cut(key, "/")
		if class == "" {
			class = firewallRuleDiagnosticClass
		}
		if strings.Count(s, "field="+residentQuote(class+"/"+field)) != 5 {
			t.Fatal("compiled field projection missing", key)
		}
	}
	for _, required := range []string{"Get-NetFirewallRule -PolicyStore PersistentStore -Name $n", "InstanceID='$n'", "Get-CimAssociatedInstance", "public_is_exact_expected", "cim_is_exact_expected", "public_is_known_8_any_code", "cim_is_known_8_any_code", "$json.Length -le 32768", "USB_MAC_ANCHOR_PROJECTION ", "catch{$row.status='unavailable';$row.fields=@()}"} {
		if !strings.Contains(s, required) {
			t.Fatal(required)
		}
	}
	if strings.Contains(s, "Write-Output $_") || strings.Contains(s, "Write-Output $prop") {
		t.Fatal("raw output")
	}
	if units := residentCommandUnits(s); units > 32766 {
		t.Fatal("readonly script command too long", units)
	}
	// Bound the largest fixed-field DTO independently of any observed values.
	rows := []map[string]any{}
	for i := 0; i < 5; i++ {
		fields := []map[string]any{}
		for _, key := range residentAnchors {
			class, field, _ := strings.Cut(key, "/")
			if class == "" {
				class = firewallRuleDiagnosticClass
			}
			fields = append(fields, map[string]any{"field": class + "/" + field, "public_count": 2, "cim_count": 2, "public_kind": "string_array", "cim_kind": "string_array", "public_is_exact_expected": false, "cim_is_exact_expected": false, "public_is_known_8_any_code": false, "cim_is_known_8_any_code": false})
		}
		rows = append(rows, map[string]any{"selector_index": i, "status": "filter_not_unique", "public_rule_count": 2, "cim_rule_count": 2, "fields": fields})
	}
	b, _ := json.Marshal(map[string]any{"schema": 1, "read_only": true, "rows": rows})
	if len(b) > 32768 {
		t.Fatal("fixed DTO exceeds byte limit", len(b))
	}
	t.Logf("fixed readonly script units=%d, full fixed DTO bytes=%d", residentCommandUnits(s), len(b))
}
