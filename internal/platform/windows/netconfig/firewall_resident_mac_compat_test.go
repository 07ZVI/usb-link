package netconfig

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func residentMacNullSnapshot(s nativeRuleSpec) firewallConstraints {
	c := expectedFirewallConstraints(s, 1)
	c[residentMacAppPath] = []string{"NULL"}
	return c
}

func TestResidentMacNullProjectionIsPrivateAndPreservesRawEvidence(t *testing.T) {
	specs := residentMacCompiledSpecs()
	if len(specs) != 5 || !residentMacAppPathReadScope(specs) {
		t.Fatal("compiled scope")
	}
	for _, s := range specs {
		got := residentMacNullSnapshot(s)
		before, _ := json.Marshal(got)
		fingerprint, _ := firewallFingerprint(got)
		if verifyResidentFirewallConstraints(got, s, 1) != nil || residentRepairAllowed(got, s) != nil {
			t.Fatal("exact expected Any rejected", s.Name)
		}
		if verifyFirewallConstraints(got, s, 1) == nil || residentConstraintTypes(got) == nil {
			t.Fatal("shared strict boundary widened")
		}
		after, _ := json.Marshal(got)
		again, _ := firewallFingerprint(got)
		if string(before) != string(after) || fingerprint != again {
			t.Fatal("raw evidence modified")
		}
		projected, _ := firewallFingerprint(residentConstraintProjection(got, s))
		if fingerprint == projected {
			t.Fatal("fingerprint canonicalized NULL")
		}
	}
}

func TestResidentMacProjectionRequiresEntireFixedReadScope(t *testing.T) {
	specs := residentMacCompiledSpecs()
	for _, size := range []int{0, 1, 3, 4} {
		if residentMacAppPathReadScope(specs[:size]) {
			t.Fatal("partial scope", size)
		}
	}
	for i := range specs {
		bad := append([]nativeRuleSpec{}, specs...)
		bad[i].Program = `C:\foreign.exe`
		if residentMacAppPathReadScope(bad) || residentMacAppPathSpec(bad[i]) {
			t.Fatal("executable scope widened")
		}
	}
	duplicate := append([]nativeRuleSpec{}, specs...)
	duplicate[4] = duplicate[0]
	if residentMacAppPathReadScope(duplicate) || residentMacAppPathReadScope(append(specs, specs[0])) {
		t.Fatal("duplicate/extra scope")
	}
}

func TestResidentMacNullStillRejectsEveryOtherConstraintGap(t *testing.T) {
	s := residentMacCompiledSpecs()[0]
	base := residentMacNullSnapshot(s)
	for key := range base {
		t.Run("missing-"+key, func(t *testing.T) {
			got := residentMacNullSnapshot(s)
			delete(got, key)
			if verifyResidentFirewallConstraints(got, s, 1) == nil || residentRepairAllowed(got, s) == nil {
				t.Fatal("incomplete constraint set")
			}
		})
	}
	for _, parts := range [][]string{nil, {}, {"EMPTY"}, {"S:"}, {"N:0"}, {"NULL", "S:Any"}, {"NULL", "NULL"}, {`S:C:\foreign.exe`}} {
		got := residentMacNullSnapshot(s)
		got[residentMacAppPath] = parts
		if verifyResidentFirewallConstraints(got, s, 1) == nil || residentRepairAllowed(got, s) == nil {
			t.Fatal("non-null AppPath accepted", parts)
		}
	}
	got := residentMacNullSnapshot(s)
	got["/foreign"] = []string{"NULL"}
	if verifyResidentFirewallConstraints(got, s, 1) == nil || residentRepairAllowed(got, s) == nil {
		t.Fatal("extra field")
	}
	for _, key := range residentAnchors {
		if key == residentMacAppPath {
			continue
		}
		got := residentMacNullSnapshot(s)
		got[key] = []string{"S:foreign"}
		if verifyResidentFirewallConstraints(got, s, 1) == nil || residentRepairAllowed(got, s) == nil {
			t.Fatal("foreign anchor", key)
		}
	}
	for _, count := range []int32{-1, 0, 2, 7, 2147483647} {
		if firewallFilterCountProven(count) {
			t.Fatal("missing/multiple related filter", count)
		}
	}
	if !firewallFilterCountProven(1) {
		t.Fatal("unique filter")
	}
}

func TestResidentMacCompatibilityDoesNotAdoptOtherRolesOrLegacy(t *testing.T) {
	for _, role := range []string{"host", "ipad", "core_mac", "core_ipad"} {
		guid, alias := "{6D7F407E-6FEF-4B41-9BD2-174B0837038D}", "USB Link Host"
		if role == "core_mac" {
			guid, alias = "{A4611646-E050-4D25-B83E-633A5598F302}", "USB Link"
		}
		// Host requires its exact fixed GUID; use the existing test constructor.
		var specs []nativeRuleSpec
		if role == "host" {
			specs = []nativeRuleSpec{residentTestSpec(t)}
		} else {
			var e error
			specs, e = residentSpecs(role, guid, alias, `C:\USB-Link.exe`)
			if e != nil {
				t.Fatal(role, e)
			}
		}
		for _, s := range specs {
			if residentMacAppPathSpec(s) || verifyResidentFirewallConstraints(residentMacNullSnapshot(s), s, 1) == nil || residentRepairAllowed(residentMacNullSnapshot(s), s) == nil {
				t.Fatal("other role widened", role)
			}
		}
	}
	s := residentMacCompiledSpecs()[1]
	s.Name = "USB-Link-BENCH-" + strings.Repeat("a", 24)
	if residentMacAppPathSpec(s) || verifyResidentFirewallConstraints(residentMacNullSnapshot(s), s, 1) == nil {
		t.Fatal("legacy token widened")
	}
}

func TestResidentMacLedgerKeepsNullAndRequiresAbsentRulesFinished(t *testing.T) {
	specs := residentMacCompiledSpecs()
	v := residentLedger{Version: 1, Role: "mac", GUID: "{A4611646-E050-4D25-B83E-633A5598F302}", Phase: "prepared", ID: strings.Repeat("a", 24), Specs: specs}
	for i, s := range specs {
		o := residentRuleObservation{}
		if i < 3 {
			o = residentRuleObservation{Present: true, Constraints: residentMacNullSnapshot(s)}
		}
		v.Before = append(v.Before, o)
	}
	if residentLedgerValid(v) != nil {
		t.Fatal("three actual rules plus two pending rules")
	}
	v.Phase = "complete"
	if residentLedgerValid(v) == nil {
		t.Fatal("absent rules falsely completed")
	}
	for i, s := range specs {
		v.Before[i] = residentRuleObservation{Present: true, Constraints: residentMacNullSnapshot(s)}
	}
	b, _ := json.Marshal(v)
	decoded, e := decodeResidentLedger(b)
	if e != nil || !reflect.DeepEqual(v, decoded) {
		t.Fatal("completed raw NULL receipt", e)
	}
	v.Phase = "removing"
	if residentLedgerValid(v) != nil {
		t.Fatal("exact uninstall obligation rejected")
	}
}
