package interfaceconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func testOwnedDAD() ownedDADLedger {
	return ownedDADLedger{Version: 1, Originals: []ownedDADOriginal{{Identity: OwnedDADIdentity{Scope: Scope{Role: "host", GUID: HostGUID, Index: 23, LUID: 123}, Instance: `SWD\WINTUN\owned`}, Original: 3}}}
}
func TestOwnedDADOriginalSurvivesDisconnectAndIndexChange(t *testing.T) {
	v := testOwnedDAD()
	current := v.Originals[0].Identity
	current.Scope.Index = 24
	if i, e := ownedDADAdmission(v, current, 0); e != nil || i != 0 {
		t.Fatal(i, e)
	}
	if i, e := ownedDADAdmission(v, current, 3); e != nil || i != 0 {
		t.Fatal(i, e)
	}
	if v.Originals[0].Original != 3 || v.Originals[0].Identity.Scope.Index != 23 {
		t.Fatal("original was projected or overwritten")
	}
	for _, mutate := range []func(*OwnedDADIdentity){func(x *OwnedDADIdentity) { x.Scope.LUID++ }, func(x *OwnedDADIdentity) { x.Instance += "other" }, func(x *OwnedDADIdentity) { x.Scope.Role = "mac" }, func(x *OwnedDADIdentity) { x.RootInstance = `USB\other` }} {
		other := current
		mutate(&other)
		if _, e := ownedDADAdmission(v, other, 0); e == nil {
			t.Fatal("foreign/new lifecycle accepted", other)
		}
	}
	if _, e := ownedDADAdmission(v, current, 1); e == nil {
		t.Fatal("external DAD change accepted")
	}
	v.RestoreRequested = true
	if _, e := ownedDADAdmission(v, current, 0); e == nil {
		t.Fatal("uninstall raced apply")
	}
}
func TestOwnedDADReceiptRequiresTypedCompleteImmutableOriginal(t *testing.T) {
	v := testOwnedDAD()
	good, _ := json.Marshal(v)
	if _, e := decodeOwnedDADLedger(good); e != nil {
		t.Fatal(e)
	}
	invalid := []string{strings.Replace(string(good), `"original":3`, `"original":3,"original":0`, 1), strings.Replace(string(good), `"original":3`, `"original":null`, 1), strings.Replace(string(good), `"original":3`, `"original":33`, 1), strings.Replace(string(good), `"serial":""`, `"serial":null`, 1), string(good) + "{}", strings.Replace(string(good), `"version":1`, `"version":1,"command":"exec"`, 1)}
	for _, b := range invalid {
		if _, e := decodeOwnedDADLedger([]byte(b)); e == nil {
			t.Fatal("bad receipt", b)
		}
	}
	changed := testOwnedDAD()
	changed.Originals[0].Original = 0
	if sameOwnedDADBaselines(v, changed) {
		t.Fatal("first original overwritten with applied zero")
	}
	changed = testOwnedDAD()
	changed.Originals[0].Identity.Scope.Index++
	if sameOwnedDADBaselines(v, changed) {
		t.Fatal("immutable receipt rebound by rewriting original")
	}
	v.RestoreRequested = true
	changed = testOwnedDAD()
	if sameOwnedDADBaselines(v, changed) {
		t.Fatal("durable uninstall cancelled")
	}
}
func TestOwnedDADIPadCannotBorrowGUIDOnly(t *testing.T) {
	id := OwnedDADIdentity{Scope: Scope{Role: "ipad", GUID: "{11853602-4376-4A50-89D8-D4ECCDAF91BB}", Index: 3, LUID: 4}, Instance: `USB\VID_05AC&PID_12AB&MI_02\child`, RootInstance: `USB\VID_05AC&PID_12AB\serial`, Driver: `{88BAE032-5A81-49F0-BC3D-A4FF138216D6}\0010`, Serial: strings.Repeat("a", 64)}
	if !validOwnedDADIdentity(id) {
		t.Fatal("complete exact target rejected")
	}
	for _, mutate := range []func(*OwnedDADIdentity){func(x *OwnedDADIdentity) { x.Serial = "" }, func(x *OwnedDADIdentity) { x.Driver = "" }, func(x *OwnedDADIdentity) { x.RootInstance = "" }, func(x *OwnedDADIdentity) { x.Instance = "ethernet" }} {
		other := id
		mutate(&other)
		if validOwnedDADIdentity(other) {
			t.Fatal("incomplete USB identity", other)
		}
	}
	v := ownedDADLedger{Version: 1, Originals: []ownedDADOriginal{{Identity: id, Original: 3}}}
	changed := id
	changed.Serial = strings.Repeat("b", 64)
	if _, e := ownedDADAdmission(v, changed, 0); e == nil {
		t.Fatal("different physical serial adopted")
	}
}
func TestOwnedDADLaunchDoesNotEnableNativeNetwork(t *testing.T) {
	base := "mac-runtime-" + strings.Repeat("a", 64)
	if e := ValidateMacOwnedDADLaunch(true, true, "unified", "fixed-gateway", base); e != nil {
		t.Fatal(e)
	}
	if e := ValidateMacOptimizationLaunch(true, false, false, true, "unified", "fixed-gateway", base); e == nil {
		t.Fatal("old gate weakened")
	}
	if e := ValidateMacOwnedDADLaunch(true, false, "unified", "fixed-gateway", base); e == nil {
		t.Fatal("unowned plan")
	}
	if e := ValidateMacOwnedDADLaunch(false, false, "legacy", "", "anything"); e != nil {
		t.Fatal("OFF changed baseline")
	}
}
