package netconfig

import (
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func TestResidentMacScriptHasOnlyExistingScopedNetworkConfiguration(t *testing.T) {
	proofs := []usbaddress.InterfaceProof{{Role: "host", GUID: usbaddress.HostGUID, Index: 8, LUID: 80, Created: 1}}
	for _, fresh := range []bool{false, true} {
		s, e := ResidentVirtualHostMacScript(9, "{A4611646-E050-4D25-B83E-633A5598F302}", 1500, proofs, fresh)
		if e != nil {
			t.Fatal(e)
		}
		for _, text := range []string{"-IPAddress '10.6.9.253' -SkipAsSource $true -PrefixLength 32", "-DestinationPrefix '10.6.9.2/32'", "WeakHostSend Enabled", "WeakHostReceive Enabled", "Forwarding Enabled", "Set-NetConnectionProfile -NetworkCategory Private"} {
			if !strings.Contains(s, text) {
				t.Fatal("missing fixed scope", text)
			}
		}
		if !strings.Contains(s, "try{$ErrorActionPreference='Stop';") || !strings.Contains(s, "}catch{Write-Output 'USB_PRIVATE_PROFILE_WARNING scoped_rules_remain_active'};") {
			t.Fatal("optional NLA profile must preserve its warning-only policy")
		}
		for _, text := range []string{"New-NetFirewallRule", "Remove-NetFirewallRule", "SetIpInterfaceEntry", "-DefaultGateway", "Set-DnsClient", "PersistentStore"} {
			if strings.Contains(s, text) {
				t.Fatal("unexpected mutation", text)
			}
		}
		if fresh == strings.Contains(s, "Start-Sleep") || fresh != strings.Contains(s, "after verified DadTransmits zero") {
			t.Fatal("DAD wait does not follow fresh proof")
		}
	}
	if _, e := ResidentVirtualHostMacScript(9, "{A4611646-E050-4D25-B83E-633A5598F302}", 1500, nil, true); e == nil {
		t.Fatal("missing shared host accepted")
	}
	if _, e := ResidentVirtualHostMacScript(9, usbaddress.HostGUID, 1500, proofs, true); e == nil {
		t.Fatal("host adapter accepted as Mac")
	}
}

func TestFreshNativeDadZeroChangesOnlyExactGeneratedMacWait(t *testing.T) {
	proof := usbaddress.InterfaceProof{Role: "host", GUID: usbaddress.HostGUID, Index: 8, LUID: 80, Created: 1}
	s, _, e := VirtualHostMacScripts(9, "{A4611646-E050-4D25-B83E-633A5598F302}", 1500, "0123456789abcdef01234567", []usbaddress.InterfaceProof{proof})
	if e != nil {
		t.Fatal(e)
	}
	fresh, e := UseFreshDADZeroMacWait(s, 9, true)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(fresh, "Start-Sleep") || !strings.Contains(fresh, "$ip.Count -ne 1") || strings.Count(fresh, "New-NetFirewallRule") != 4 {
		t.Fatal("unexpected generated wait change")
	}
	for _, unknown := range []string{fresh, s + s, strings.Replace(s, "AddSeconds(15)", "AddSeconds(16)", 1)} {
		if _, e := UseFreshDADZeroMacWait(unknown, 9, true); e == nil {
			t.Fatal("unknown wait adopted")
		}
	}
}
