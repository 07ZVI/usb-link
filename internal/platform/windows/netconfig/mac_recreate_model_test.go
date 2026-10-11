package netconfig

import (
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func TestFixedMacNativeDoesNotBroadenHostGate(t *testing.T) {
	f := nativeHostInterface{GUID: "{A4611646-E050-4D25-B83E-633A5598F302}", Alias: "USB Link", Type: 53, Index: 8, LUID: 80}
	if _, e := validateNativeWintunInterface([]nativeHostInterface{f}, 8, f.GUID, f.Alias); e != nil {
		t.Fatal(e)
	}
	if _, e := validateNativeHostInterface([]nativeHostInterface{f}, 8); e == nil {
		t.Fatal("Mac became shared host")
	}
	for name, rows := range map[string][]nativeHostInterface{"duplicate": {f, f}, "same_name_foreign_guid": {func() nativeHostInterface { x := f; x.GUID = usbaddress.HostGUID; return x }()}, "mapping_changed": {func() nativeHostInterface { x := f; x.Index++; return x }()}, "wrong_type": {func() nativeHostInterface { x := f; x.Type = 6; return x }()}} {
		t.Run(name, func(t *testing.T) {
			if _, e := validateNativeWintunInterface(rows, 8, f.GUID, f.Alias); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, e := validateNativeWintunInterface([]nativeHostInterface{f}, 8, "{12345678-1234-1234-1234-123456789ABC}", f.Alias); e == nil {
		t.Fatal("arbitrary GUID accepted")
	}
}
