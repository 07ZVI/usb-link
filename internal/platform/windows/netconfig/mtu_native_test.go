package netconfig

import "testing"

func TestVerifiedMacMTUNativeScopeAndReuseRejection(t *testing.T) {
	guid := "{A4611646-E050-4D25-B83E-633A5598F302}"
	for _, mtu := range []int{1500, 9000, 16000} {
		if err := validateVerifiedMacMTUScope(5, guid, 9, mtu); err != nil {
			t.Fatal(err)
		}
	}
	for _, mtu := range []int{0, 1499, 9001, 65535} {
		if err := validateVerifiedMacMTUScope(5, guid, 9, mtu); err == nil {
			t.Fatal("accepted unproved MTU")
		}
	}
	for _, input := range []macMTUIdentity{{Index: 0, LUID: 9, GUID: guid}, {Index: 5, LUID: 0, GUID: guid}, {Index: 5, LUID: 9, GUID: "invalid"}} {
		if err := validateVerifiedMacMTUScope(input.Index, input.GUID, input.LUID, 1500); err == nil {
			t.Fatal("accepted invalid identity scope")
		}
	}
	owned := macMTUIdentity{Index: 5, LUID: 9, GUID: guid, Alias: "USB Link", Type: 53}
	foreign := macMTUIdentity{Index: 6, LUID: 10, GUID: "{E4611646-E050-4D25-B83E-633A5598F302}", Alias: "Wi-Fi", Type: 71}
	if err := validateVerifiedMacMTUIdentity([]macMTUIdentity{owned, foreign}, 5, guid, 9); err != nil {
		t.Fatal(err)
	}
	for _, rows := range [][]macMTUIdentity{nil, {foreign}, {owned, owned}, {owned, {Index: 6, LUID: 10, GUID: foreign.GUID, Alias: "USB Link", Type: 53}}, {{Index: 5, LUID: 10, GUID: guid, Alias: "USB Link", Type: 53}}, {{Index: 5, LUID: 9, GUID: guid, Alias: "USB Link Host", Type: 53}}, {{Index: 5, LUID: 9, GUID: guid, Alias: "USB Link", Type: 71}}, {owned, {Index: 5, LUID: 10, GUID: foreign.GUID, Alias: "Wi-Fi", Type: 71}}} {
		if err := validateVerifiedMacMTUIdentity(rows, 5, guid, 9); err == nil {
			t.Fatalf("accepted absent/duplicate/reused/conflicting identity: %+v", rows)
		}
	}
}
