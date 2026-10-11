package netconfig

import (
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func TestVirtualHostMacDoesNotDuplicateWindowsServiceAddress(t *testing.T) {
	g := "{A4611646-E050-4D25-B83E-633A5598F302}"
	token := "0123456789abcdef01234567"
	proof := usbaddress.InterfaceProof{Index: 9, LUID: 88, GUID: usbaddress.HostGUID, Role: "host", Created: 1}
	s, _, e := VirtualHostMacScripts(7, g, 1500, token, []usbaddress.InterfaceProof{proof})
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"-IPAddress '10.6.9.253' -SkipAsSource $true -PrefixLength 32", "Set-NetIPInterface -InterfaceIndex 7 -AddressFamily IPv4 -WeakHostSend Enabled -WeakHostReceive Enabled -Forwarding Enabled -PolicyStore ActiveStore", "-DestinationPrefix '10.6.9.2/32'", "-LocalAddress '10.6.9.1'"} {
		if !strings.Contains(s, v) {
			t.Fatal(v)
		}
	}
	if strings.Contains(s, "-IPAddress '10.6.9.1'") || strings.Contains(s, "-PrefixLength 24") {
		t.Fatal("duplicated address")
	}
	if _, _, e = VirtualHostMacScripts(7, g, 1500, token, nil); e == nil {
		t.Fatal("missing host proof")
	}
	proof.GUID = g
	if _, _, e = VirtualHostMacScripts(7, g, 1500, token, []usbaddress.InterfaceProof{proof}); e == nil {
		t.Fatal("foreign host GUID")
	}
	rule, e := SharedHostServicesRule(`C:\Program Files\USB Link\0.8.29\USB-Link.exe`)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(rule, "New-NetFirewallRule") != 4 || strings.Contains(rule, "-Protocol UDP") || strings.Contains(rule, "-RemoteAddress 'Any'") || !strings.Contains(rule, "USB-Link-Core-Host-iPad-v1") || !strings.Contains(rule, usbaddress.HostGUID) {
		t.Fatal("host service scope", rule)
	}
	for _, scope := range []string{"-Program 'System'", "-Service 'LanmanServer'", "-LocalPort 445", "-RemoteAddress '10.6.9.2'", "-RemoteAddress '10.6.9.3'", "-LocalAddress '10.6.9.1'"} {
		if !strings.Contains(rule, scope) {
			t.Fatal("missing native SMB scope", scope)
		}
	}
	recover, e := RecoverAdapter(usbaddress.HostGUID, token)
	if e != nil || !strings.Contains(recover, "Name -cne 'USB Link Host'") || !strings.Contains(recover, "Service -ine 'Wintun'") || strings.Contains(recover, "/delete-driver") {
		t.Fatal("host cleanup scope", e)
	}
}
