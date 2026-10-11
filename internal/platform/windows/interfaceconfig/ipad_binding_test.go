package interfaceconfig

import (
	"encoding/json"
	"strings"
	"suhang/usbnet/internal/transport/ipadsession"
	"testing"
)

func ipadBindingFixture() IPadPersistentBinding {
	s := Scope{Role: "ipad", GUID: "{01234567-89AB-CDEF-0123-456789ABCDEF}", Index: 8, LUID: 900}
	return IPadPersistentBinding{Version: 1, Root: `USB\VID_05AC&PID_12AB\ABCDEF123456789012345678`, Driver: `{88BAE032-5A81-49F0-BC3D-A4FF138216D6}\0001`, Instance: `USB\VID_05AC&PID_12AB&MI_02\CHILD123`, SerialSHA256: strings.Repeat("a", 64), Scope: s, State: "pending", Persistent: true, Plan: ipadsession.Plan{Version: 5, GUID: s.GUID, Index: s.Index, LUID: s.LUID, ServerIP: "10.6.9.1", Token: strings.Repeat("b", 24), PlannedAt: 123, HostFlags: &ipadsession.HostFlags{Send: false, Receive: true}}}
}
func TestIPadPendingRecordsBeforeCompletedCreation(t *testing.T) {
	pending := ipadBindingFixture()
	b, e := json.Marshal(pending)
	if e != nil {
		t.Fatal(e)
	}
	got, e := decodeIPadBinding(b)
	if e != nil || !sameIPadBinding(got, pending) || got.Plan.CreatedAt != 0 {
		t.Fatal(got, e)
	}
	// False is explicit, so damaged/missing fields cannot manufacture an original.
	for _, bad := range []string{strings.Replace(string(b), `,"forward":false`, "", 1), strings.Replace(string(b), `"persistent":true`, `"persistent":null`, 1), strings.Replace(string(b), `"state":"pending"`, `"state":"ready"`, 1), string(b) + "{}", strings.Replace(string(b), `"version":1`, `"version":1,"version":1`, 1)} {
		if _, e := decodeIPadBinding([]byte(bad)); e == nil {
			t.Fatalf("accepted damaged original: %s", bad)
		}
	}
}
func TestIPadCrashPhaseCannotBecomeReadyWithoutOriginalProof(t *testing.T) {
	pending := ipadBindingFixture()
	address := pending
	address.State = "address"
	address.Plan.CreatedAt = 234
	ready := address
	ready.State = "ready"
	ready.Plan.Version = 6
	ready.Plan.AddressMode = "legacy"
	ready.Plan.PersistentSHA256 = strings.Repeat("c", 64)
	if !ipadBindingTransition(pending, address) || !ipadBindingTransition(address, ready) {
		t.Fatal("valid chain rejected")
	}
	// Every crash prefix stays pending/address; nothing can skip address proof,
	// replace the target, recapture changed originals, or adopt an unknown mapping.
	if ipadBindingTransition(pending, ready) {
		t.Fatal("pending adopted ready")
	}
	for _, change := range []func(*IPadPersistentBinding){func(v *IPadPersistentBinding) { v.Scope.LUID++; v.Plan.LUID++ }, func(v *IPadPersistentBinding) { v.Scope.Index++; v.Plan.Index++ }, func(v *IPadPersistentBinding) { v.Root += "OTHER" }, func(v *IPadPersistentBinding) { v.Instance += "OTHER" }, func(v *IPadPersistentBinding) { v.SerialSHA256 = strings.Repeat("d", 64) }, func(v *IPadPersistentBinding) { v.Plan.HostFlags = &ipadsession.HostFlags{Send: true, Receive: true} }, func(v *IPadPersistentBinding) { v.Plan.PersistentSHA256 = "" }} {
		bad := ready
		change(&bad)
		if ipadBindingTransition(address, bad) {
			t.Fatal("foreign/damaged phase accepted", bad)
		}
	}
	restore := ready
	restore.State = "restoring"
	if !ipadBindingTransition(ready, restore) || ipadBindingTransition(restore, ready) {
		t.Fatal("restoring reopened ordinary ready")
	}
}
func TestIPadDADOnlyDoesNotInventPersistentOriginal(t *testing.T) {
	pending := ipadBindingFixture()
	pending.Persistent = false
	complete := pending
	complete.State = "ephemeral"
	complete.Plan.CreatedAt = 456
	if !ipadBindingTransition(pending, complete) {
		t.Fatal("DAD-only checkpoint rejected")
	}
	bad := complete
	bad.State = "ready"
	bad.Plan.Version = 6
	bad.Plan.AddressMode = "persistent"
	bad.Plan.PersistentSHA256 = strings.Repeat("c", 64)
	if bad.valid() || ipadBindingTransition(complete, bad) {
		t.Fatal("DAD-only manufactured Store ownership")
	}
	b, _ := json.Marshal(complete)
	v, e := decodeIPadBinding(b)
	if e != nil || v.Persistent {
		t.Fatal(v, e)
	}
}

func TestIPadOriginalSelectionPreservesOtherRoles(t *testing.T) {
	host := Scope{Role: "host", GUID: HostGUID, Index: 1, LUID: 1}
	mac := Scope{Role: "mac", GUID: MacGUID, Index: 2, LUID: 2}
	ipad := ipadBindingFixture().Scope
	r := configReceipt{Version: 1, DAD: []dadOriginal{{Scope: host, Original: 1}, {Scope: mac, Original: 2}}, Persistent: []persistentOriginal{{Scope: host}, {Scope: mac}}}
	if ipadOriginalsPending(r) {
		t.Fatal("other roles blocked iPad absence/capture")
	}
	r.DAD = append(r.DAD, dadOriginal{Scope: ipad, Original: 3})
	if !ipadOriginalsPending(r) {
		t.Fatal("iPad original ignored")
	}
	r.DAD = r.DAD[:2]
	r.Persistent = append(r.Persistent, persistentOriginal{Scope: ipad})
	if !ipadOriginalsPending(r) {
		t.Fatal("iPad Store original ignored")
	}
	// Selection itself consumes neither host nor Mac and is independent of global
	// uninstall intent; global final-store-empty remains a separate contract.
	if len(r.DAD) != 2 || len(r.Persistent) != 3 || r.DAD[0].Scope != host || r.DAD[1].Scope != mac {
		t.Fatal("other original lost")
	}
	r.RestoreRequested = true
	if !ipadOriginalsPending(r) {
		t.Fatal("restore intent hid obligation")
	}
}
