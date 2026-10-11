package netconfig

import (
	"errors"
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func TestRecoveryProfileIdentityRequiresExactOwnedTuple(t *testing.T) {
	host := OwnedProfileRecoveryIdentity{Role: "host", GUID: usbaddress.HostGUID, Index: 28, LUID: 280}
	row := nativeHostInterface{GUID: host.GUID, Alias: usbaddress.HostName, Type: 53, Index: 28, LUID: 280}
	if e := validateProfileRecoveryMapping(host, []nativeHostInterface{row}); e != nil {
		t.Fatal(e)
	}
	mac := OwnedProfileRecoveryIdentity{Role: "mac", GUID: "{A4611646-E050-4D25-B83E-633A5598F302}", Index: 29, LUID: 290}
	mr := nativeHostInterface{GUID: mac.GUID, Alias: "USB Link", Type: 53, Index: 29, LUID: 290}
	if e := validateProfileRecoveryMapping(mac, []nativeHostInterface{row, mr}); e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*OwnedProfileRecoveryIdentity){
		"empty role": func(p *OwnedProfileRecoveryIdentity) { p.Role = "" }, "foreign GUID": func(p *OwnedProfileRecoveryIdentity) { p.GUID = mac.GUID }, "unproven iPad": func(p *OwnedProfileRecoveryIdentity) { p.Role = "ipad" }, "zero index": func(p *OwnedProfileRecoveryIdentity) { p.Index = 0 }, "changed index": func(p *OwnedProfileRecoveryIdentity) { p.Index++ }, "changed LUID": func(p *OwnedProfileRecoveryIdentity) { p.LUID++ }} {
		t.Run(name, func(t *testing.T) {
			p := host
			change(&p)
			if validateProfileRecoveryMapping(p, []nativeHostInterface{row}) == nil {
				t.Fatal("unproved identity admitted")
			}
		})
	}
	for name, rows := range map[string][]nativeHostInterface{"absent": nil, "duplicate": {row, row}, "aliasonly": {{GUID: mac.GUID, Alias: row.Alias, Index: 29, LUID: 290, Type: 53}}, "collision index": {row, {GUID: mac.GUID, Alias: mr.Alias, Index: row.Index, LUID: 290, Type: 53}}, "collision LUID": {row, {GUID: mac.GUID, Alias: mr.Alias, Index: 29, LUID: row.LUID, Type: 53}}, "wrong type": {{GUID: row.GUID, Alias: row.Alias, Index: row.Index, LUID: row.LUID, Type: 6}}} {
		t.Run(name, func(t *testing.T) {
			if validateProfileRecoveryMapping(host, rows) == nil {
				t.Fatal("ambiguous mapping admitted")
			}
		})
	}
}
func TestRecoveryProfileOwnerAndMappingRechecked(t *testing.T) {
	for _, x := range []struct {
		name string
		fail int
	}{{"success", 0}, {"owner initial", 1}, {"mapping initial", 2}, {"driver", 3}, {"mapping changed", 4}, {"owner changed", 5}, {"cancelled", 6}} {
		t.Run(x.name, func(t *testing.T) {
			step := 0
			failure := errors.New("unproven")
			f := func() error {
				step++
				if step == x.fail {
					return failure
				}
				return nil
			}
			e := runProfileRecoveryIdentity(f, f, f, f)
			if (x.fail == 0 && (e != nil || step != 6)) || (x.fail != 0 && (e != failure || step != x.fail)) {
				t.Fatal(step, e)
			}
		})
	}
}
func TestRecoveryMacNodeCannotChangeHostAdmission(t *testing.T) {
	n := validNativeHostNode()
	mac := "{A4611646-E050-4D25-B83E-633A5598F302}"
	n.SetupNetGUID = mac
	n.CMNetGUID = mac
	if e := validateNativeWintunNodeForGUID(n, mac); e != nil {
		t.Fatal(e)
	}
	if validateNativeHostNode(n) == nil {
		t.Fatal("Mac node became host proof")
	}
	if validateNativeWintunNodeForGUID(n, "{00000000-0000-0000-0000-000000000001}") == nil {
		t.Fatal("arbitrary Wintun node admitted")
	}
	n.Service = "AppleUsbNcm"
	if validateNativeWintunNodeForGUID(n, mac) == nil {
		t.Fatal("foreign driver admitted")
	}
}
