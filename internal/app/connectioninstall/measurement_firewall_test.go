package connectioninstall

import (
	"strings"
	"testing"
)

func TestMeasurementFirewallScopeAndTimeoutOwnership(t *testing.T) {
	id := strings.Repeat("a", 32)
	s, err := measurementFirewallScript(true, "{12345678-1234-1234-1234-123456789012}", id, `C:\USB's\USB-Link.exe`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-Protocol UDP -LocalPort 10691", "-RemoteAddress '10.6.9.2' -LocalAddress '10.6.9.1'", "-InterfaceAlias $a[0].Name", "-Program 'C:\\USB''s\\USB-Link.exe'", "InterfaceGuid -eq", "Group -cne", "Name -ceq 'USB Link'"} {
		if !strings.Contains(s, want) {
			t.Fatal(want, s)
		}
	}
	cleanup, err := measurementFirewallScript(false, "", id, "")
	if err != nil || !strings.Contains(cleanup, "Description -ceq '"+id+"'") || strings.Contains(cleanup, "New-NetFirewallRule") {
		t.Fatal(cleanup, err)
	}
	for _, invalid := range []string{"abc';Remove-NetFirewallRule", "", "192.168.1.1"} {
		if _, err := measurementFirewallScript(true, invalid, id, `C:\USB-Link.exe`); err == nil {
			t.Fatal(invalid)
		}
	}
	if _, err := measurementFirewallScript(true, "12345678-1234-1234-1234-123456789012", "../escape", `C:\USB-Link.exe`); err == nil {
		t.Fatal("invalid nonce accepted")
	}
}
