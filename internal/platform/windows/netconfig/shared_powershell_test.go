package netconfig

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func TestSharedSubnetConflictProofs(t *testing.T) {
	pwsh := os.Getenv("SUHANG_TEST_PWSH")
	if pwsh == "" {
		t.Skip("PowerShell fixture unavailable")
	}
	g := "{12345678-1234-1234-1234-123456789abc}"
	script, e := usbaddress.ConflictScript(8, g, []usbaddress.InterfaceProof{{Index: 7, GUID: g, LUID: 1}})
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name, prefix, ip, proofGUID string
		index                       int
		failure                     bool
	}{
		{"owned-peer", "10.6.9.2/32", "10.6.9.1", g, 7, false},
		{"foreign-interface", "10.6.9.2/32", "10.6.9.1", g, 9, true},
		{"ambiguous-subnet", "10.6.9.0/24", "10.6.9.1", g, 7, true},
		{"stale-interface-proof", "10.6.9.2/32", "10.6.9.1", "{22345678-1234-1234-1234-123456789abc}", 7, true},
		{"foreign-local-address", "10.6.9.2/32", "10.6.9.4", g, 7, true},
		{"foreign-covering-route", "10.0.0.0/8", "10.6.9.1", g, 7, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := fmt.Sprintf(`function Get-NetAdapter {[CmdletBinding()]param([switch]$IncludeHidden);[pscustomobject]@{ifIndex=8;InterfaceGuid='%s'};[pscustomobject]@{ifIndex=7;InterfaceGuid='%s'}}
function Get-NetRoute {[CmdletBinding()]param($AddressFamily,$PolicyStore);[pscustomobject]@{DestinationPrefix='%s';InterfaceIndex=%d;NextHop='0.0.0.0'};[pscustomobject]@{DestinationPrefix='0.0.0.0/0';InterfaceIndex=9;NextHop='192.168.1.1'}}
function Get-NetIPAddress {[CmdletBinding()]param($AddressFamily);[pscustomobject]@{IPAddress='%s';InterfaceIndex=%d;PrefixLength=32}}
`, g, tc.proofGUID, tc.prefix, tc.index, tc.ip, tc.index)
			out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command", fixture+script+"Write-Output 'OK'").CombinedOutput()
			if (err != nil) != tc.failure {
				t.Fatalf("%v %s", err, out)
			}
		})
	}
}
func TestSharedMacUsesOnlyHostRoutes(t *testing.T) {
	g := "{A4611646-E050-4D25-B83E-633A5598F302}"
	s, _, e := SharedProfileScripts(7, g, 1500, "0123456789abcdef01234567", nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"-PrefixLength 32", "-DestinationPrefix '10.6.9.2/32'", "-NextHop '0.0.0.0'", "USB subnet conflicts"} {
		if !strings.Contains(s, v) {
			t.Fatal("missing", v)
		}
	}
	if strings.Contains(s, "-PrefixLength 24") || strings.Contains(s, "WeakHost") {
		t.Fatal("ambiguous or broad routing")
	}
}
func TestCorePermissionRejectsUnownedArguments(t *testing.T) {
	g := "{A4611646-E050-4D25-B83E-633A5598F302}"
	s, e := CoreServicesRule(g, "10.6.9.2", `D:\Program Files\USB Link\0.8.27\USB-Link.exe`)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"-PolicyStore PersistentStore", "-Program 'D:", "-RemoteAddress '10.6.9.2'", "-LocalAddress '10.6.9.1'", "-InterfaceAlias $a[0].Name", "Core rule ownership changed", "Get-NetFirewallApplicationFilter"} {
		if !strings.Contains(s, v) {
			t.Fatal("missing", v)
		}
	}
	for _, peer := range []string{"any", "10.6.9.0/24", "10.6.10.2", "';bad"} {
		if _, e := CoreServicesRule(g, peer, `C:\USB-Link.exe`); e == nil {
			t.Fatal(peer)
		}
	}
}

func TestCorePermissionRefreshAndForeignRuleProtection(t *testing.T) {
	resetCoreBaselineFixture(t)
	pwsh := os.Getenv("SUHANG_TEST_PWSH")
	if pwsh == "" {
		t.Skip("PowerShell fixture unavailable")
	}
	g := "{A4611646-E050-4D25-B83E-633A5598F302}"
	first, _ := CoreServicesRule(g, "10.6.9.2", `C:\Program Files\USB Link\0.8.26\USB-Link.exe`)
	next, _ := CoreServicesRule(g, "10.6.9.2", `C:\Program Files\USB Link\0.8.27\USB-Link.exe`)
	fixture := coreFirewallFixture

	for _, tc := range []struct {
		name, script, check string
		fail                bool
	}{
		{"upgrade-refresh", first + next, `if($global:rules.Count -ne 2 -or $global:removed -ne 2 -or $global:rules['USB-Link-Core-Mac-v1'].App.Program -ne 'C:\Program Files\USB Link\0.8.27\USB-Link.exe'){throw 'refresh failed'}`, false},
		{"foreign-rule", `$global:rules['USB-Link-Core-Mac-v1']=[pscustomobject]@{Group='foreign';Description='foreign'};` + next, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, e := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command", fixture+tc.script+tc.check).CombinedOutput()
			if (e != nil) != tc.fail {
				t.Fatalf("%v %s", e, out)
			}
			if tc.fail && !strings.Contains(string(out), "Core rule ownership changed") {
				t.Fatalf("wrong failure %s", out)
			}
		})
	}
}
