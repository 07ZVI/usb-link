package netconfig

import (
	"strings"
	"testing"
)

func TestResidentMacNullProjectionIsFixedAndReadOnly(t *testing.T) {
	s := ResidentMacNullProjectionScript()
	for _, name := range []string{"USB-Link-Resident-Mac-ICMP-v1", "USB-Link-Resident-Mac-BENCH-v1", "USB-Link-Resident-Mac-SUN-TCP-v1", "USB-Link-Resident-Mac-SUN-UDP-v1", "USB-Link-Resident-Mac-FILES-v1"} {
		if strings.Count(s, "'"+name+"'") != 1 {
			t.Fatalf("fixed selector missing or repeated: %s", name)
		}
	}
	for _, write := range []string{"Set-Net", "New-Net", "Remove-Net", "Enable-Net", "Disable-Net", "Set-Cim", "New-Cim", "Remove-Cim", "Invoke-Cim", "Put_", "Out-File", "Set-Content", "Add-Content"} {
		if strings.Contains(s, write) {
			t.Fatalf("mutation %s", write)
		}
	}
	for _, read := range []string{"Get-NetFirewallRule -Name $n", "Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule", "Get-CimInstance -Namespace root/standardcimv2", "Get-CimAssociatedInstance -InputObject", "$json.Length -le 4096", "USB_MAC_NULL_PROJECTION "} {
		if !strings.Contains(s, read) {
			t.Fatalf("missing bounded read contract: %s", read)
		}
	}
	// A missing public projection is distinct from a present NULL property;
	// neither becomes Any. The complete result contains only fixed shapes.
	for _, check := range []string{"return @('missing',$false)", "return @('null',$false)", "return @('other',$false)", "[StringComparison]::OrdinalIgnoreCase", "catch{$row.status='unavailable'}"} {
		if !strings.Contains(s, check) {
			t.Fatal(check)
		}
	}
	if strings.Contains(s, "Write-Output $prop") || strings.Contains(s, "Write-Output $_") || strings.Contains(s, "$row.public_program=") || strings.Contains(s, "$row.cim_app_path=") {
		t.Fatal("diagnostic leaks a value or raw error")
	}
}
