package netconfig

import (
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func TestMacPathScopeIncludesFallbackAndNeverIPad(t *testing.T) {
	mac := usbaddress.InterfaceProof{Index: 5, LUID: 50, GUID: "{A4611646-E050-4D25-B83E-633A5598F302}"}
	host := usbaddress.InterfaceProof{Index: 6, LUID: 60, GUID: usbaddress.HostGUID, Role: "host", Created: 100}
	ipad := usbaddress.InterfaceProof{Index: 7, LUID: 70, GUID: "{C839CF3F-7F98-4CB3-891B-36E4FC772970}"}
	for _, mtu := range []int{1500, 9000, 16000} {
		targets, err := macPathTargets(mac, []usbaddress.InterfaceProof{ipad, host}, mtu)
		if err != nil || len(targets) != 2 || targets[0] != mac || targets[1] != host {
			t.Fatalf("MTU %d: %v %v", mtu, targets, err)
		}
		if targets, err = macPathTargets(mac, nil, mtu); err != nil || len(targets) != 1 {
			t.Fatalf("standalone: %v %v", targets, err)
		}
	}
	bad := host
	bad.Created = 0
	for _, scope := range [][]usbaddress.InterfaceProof{{bad}, {host, host}, {host, ipad, ipad, ipad, ipad}} {
		if _, err := macPathTargets(mac, scope, 9000); err == nil {
			t.Fatal("invalid scope accepted")
		}
	}
	if _, err := macPathTargets(mac, nil, 65535); err == nil {
		t.Fatal("unproven MTU accepted")
	}
	foreign := mac
	foreign.GUID = ipad.GUID
	if _, err := macPathTargets(foreign, []usbaddress.InterfaceProof{host}, 1500); err == nil {
		t.Fatal("foreign adapter accepted")
	}
}
