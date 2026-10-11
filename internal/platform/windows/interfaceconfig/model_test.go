package interfaceconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExactScopeAndOriginalReceipt(t *testing.T) {
	host := Scope{Role: "host", GUID: HostGUID, Index: 7, LUID: 9}
	r := configReceipt{Version: 1, DAD: []dadOriginal{{Scope: host, Original: 1}}, Persistent: []persistentOriginal{{Scope: host, OriginalMTU: 1500, DesiredMTU: 1500, AddressAbsent: true, Address: "10.6.9.1", Prefix: 32}}}
	b, _ := json.Marshal(r)
	if _, e := decodeConfigReceipt(b); e != nil {
		t.Fatal(e)
	}
	for _, replacement := range [][2]string{{`"version":1`, `"version":1,"version":1`}, {HostGUID, MacGUID}, {`"address_absent":true`, `"address_absent":false`}, {`"prefix":32`, `"prefix":24`}, {`"index":7`, `"index":0`}, {`"luid":9`, `"luid":0`}, {`"original":1`, `"original":33`}, {`"role":"host"`, `"role":"other"`}} {
		if _, e := decodeConfigReceipt([]byte(strings.ReplaceAll(string(b), replacement[0], replacement[1]))); e == nil {
			t.Errorf("accepted %s", replacement[1])
		}
	}
}
func TestOriginalsNeverRebasedByLiveZero(t *testing.T) {
	s := Scope{Role: "mac", GUID: MacGUID, Index: 5, LUID: 8}
	a := configReceipt{Version: 1, DAD: []dadOriginal{{s, 3}}}
	b := configReceipt{Version: 1, DAD: []dadOriginal{{s, 0}}}
	if sameConfigBaselines(a, b) {
		t.Fatal("recapture disabled live value")
	}
	b = a
	b.DAD = append([]dadOriginal{}, a.DAD...)
	b.DAD[0].Scope.LUID++
	if sameConfigBaselines(a, b) {
		t.Fatal("new LUID reused original authority")
	}
	b = configReceipt{Version: 1}
	if !sameConfigBaselines(a, b) {
		t.Fatal("verified checkpoint cannot consume")
	}
}
func TestPersistentCreationMetadataCannotRewriteOriginal(t *testing.T) {
	s := Scope{Role: "host", GUID: HostGUID, Index: 5, LUID: 8}
	a := configReceipt{Version: 1, Persistent: []persistentOriginal{{Scope: s, OriginalMTU: 9000, DesiredMTU: 1500, AddressAbsent: true, Address: "10.6.9.1", Prefix: 32}}}
	b := configReceipt{Version: 1, Persistent: append([]persistentOriginal{}, a.Persistent...)}
	b.Persistent[0].AppliedAddress = &addressBaseline{"infinite", "infinite"}
	b.Persistent[0].Profile = &profileOriginal{MacGUID, 0}
	if !sameConfigBaselines(a, b) {
		t.Fatal("creation readback rejected")
	}
	a = b
	b.Persistent = append([]persistentOriginal{}, a.Persistent...)
	b.Persistent[0].OriginalMTU = 1500
	if sameConfigBaselines(a, b) {
		t.Fatal("original MTU replaced")
	}
	b.Persistent[0] = a.Persistent[0]
	b.Persistent[0].AppliedAddress = &addressBaseline{"changed", "infinite"}
	if sameConfigBaselines(a, b) {
		t.Fatal("created policy rebased")
	}
}

func TestPerInstancePersistentRolesRemainBounded(t *testing.T) {
	for _, s := range []Scope{{Role: "mac", GUID: MacGUID, Index: 7, LUID: 9}, {Role: "ipad", GUID: "{12345678-ABCD-1234-ABCD-123456789ABC}", Index: 17, LUID: 19}} {
		r := configReceipt{Version: 1, Persistent: []persistentOriginal{{Scope: s, OriginalMTU: 9000, DesiredMTU: 1500, AddressAbsent: true, Address: scopeAddress(s), Prefix: 32}}}
		b, _ := json.Marshal(r)
		if _, e := decodeConfigReceipt(b); e != nil {
			t.Fatal(s, e)
		}
		r.Persistent[0].Address = "10.6.10.1"
		b, _ = json.Marshal(r)
		if _, e := decodeConfigReceipt(b); e == nil {
			t.Fatal("foreign subnet admitted")
		}
	}
}

func TestUninstallIntentCannotBeClearedAroundOriginals(t *testing.T) {
	a := configReceipt{Version: 1, RestoreRequested: true, DAD: []dadOriginal{{Scope: Scope{Role: "host", GUID: HostGUID, Index: 7, LUID: 9}, Original: 1}}}
	b := a
	b.RestoreRequested = false
	if sameConfigBaselines(a, b) {
		t.Fatal("durable uninstall intent cleared")
	}
	b = a
	b.DAD = nil
	if !sameConfigBaselines(a, b) {
		t.Fatal("verified obligation checkpoint prohibited")
	}
}
