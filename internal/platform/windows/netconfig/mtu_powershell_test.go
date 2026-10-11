package netconfig

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Execute the production PowerShell against a provider-shaped fixture exposing
// NlMtu only. Cmdlet parameter NlMtuBytes is intentionally not an object property.
// This is script behavior evidence, not a Windows network-provider integration.
func TestPowerShellVerifiedMTUReadback(t *testing.T) {
	pwsh := os.Getenv("SUHANG_TEST_PWSH")
	if pwsh == "" {
		t.Skip("PowerShell fixture host not configured")
	}
	guid := "{A4611646-E050-4D25-B83E-633A5598F302}"
	for _, c := range []struct {
		name, mode string
		mtu        int
		failure    string
		legacy     bool
	}{
		{"9000", "ok", 9000, "", false}, {"16000", "ok", 16000, "", false}, {"fallback1500", "ok", 1500, "", false},
		{"setting_not_effective", "noop", 16000, "MTU readback mismatch", false},
		{"fallback_not_effective", "noop", 1500, "MTU readback mismatch", false},
		{"ambiguous_interface", "duplicate", 16000, "MTU readback mismatch", false},
		{"provider_failure", "query-fail", 16000, "fixture provider unavailable", false},
		{"set_denied", "set-denied", 16000, "fixture set denied", false},
		{"adapter_replaced", "wrong-guid", 16000, "Owned adapter identity mismatch", false},
		{"0823_wrong_property_reproduction", "ok", 16000, "MTU readback mismatch", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			script, e := VerifiedMTUScript(7, guid, c.mtu)
			if e != nil {
				t.Fatal(e)
			}
			if c.legacy {
				script = strings.ReplaceAll(script, ".NlMtu", ".NlMtuBytes")
			}
			fixture := fmt.Sprintf(`$global:mode='%s';$global:mtu=9000;
function Get-NetAdapter { [CmdletBinding()] param([switch]$IncludeHidden);$g='%s';if($global:mode -eq 'wrong-guid'){$g='{00000000-0000-0000-0000-000000000000}'};[pscustomobject]@{ifIndex=7;InterfaceGuid=$g;Name='USB Link'} }
function Set-NetIPInterface { [CmdletBinding()] param([uint32]$InterfaceIndex,[string]$AddressFamily,[uint32]$NlMtuBytes,[string]$PolicyStore);if($InterfaceIndex -ne 7 -or $AddressFamily -ne 'IPv4' -or $PolicyStore -ne 'ActiveStore'){throw 'fixture scope changed'};if($global:mode -eq 'set-denied'){throw 'fixture set denied'};if($global:mode -ne 'noop'){$global:mtu=$NlMtuBytes} }
function Get-NetIPInterface { [CmdletBinding()] param([uint32]$InterfaceIndex,[string]$AddressFamily,[string]$PolicyStore);if($InterfaceIndex -ne 7 -or $AddressFamily -ne 'IPv4' -or $PolicyStore -ne 'ActiveStore'){throw 'fixture query scope changed'};if($global:mode -eq 'query-fail'){throw 'fixture provider unavailable'};$r=[pscustomobject]@{InterfaceIndex=7;AddressFamily=2;NlMtu=$global:mtu};$r;if($global:mode -eq 'duplicate'){$r} }
`, c.mode, guid)
			b, e := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command", fixture+diagnosticScript(script)).CombinedOutput()
			text := string(b)
			if c.failure != "" {
				if e == nil || !strings.Contains(text, c.failure) || strings.Contains(text, "SUHANG_NETWORK_SCRIPT_OK") {
					t.Fatalf("failure masked: %v %s", e, text)
				}
			} else if e != nil || !strings.Contains(text, fmt.Sprintf("VERIFIED_IP_MTU=%d", c.mtu)) || !strings.Contains(text, "SUHANG_NETWORK_SCRIPT_OK") {
				t.Fatalf("readback rejected: %v %s", e, text)
			}
		})
	}
}
