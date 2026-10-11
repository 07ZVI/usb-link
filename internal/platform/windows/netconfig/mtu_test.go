package netconfig

import (
	"strings"
	"testing"
)

func TestVerifiedMTUScope(t *testing.T) {
	g := "{00000000-0000-0000-0000-000000000001}"
	for _, m := range []int{1500, 9000, 16000} {
		s, e := VerifiedMTUScript(7, g, m)
		if e != nil {
			t.Fatal(e)
		}
		for _, want := range []string{"ifIndex -eq 7", "InterfaceGuid", "Name -ceq 'USB Link'", "-PolicyStore ActiveStore", "MTU readback mismatch"} {
			if !strings.Contains(s, want) {
				t.Fatal(want)
			}
		}
		for _, bad := range []string{"New-NetIPAddress", "New-NetRoute", "Firewall", "DNS"} {
			if strings.Contains(s, bad) {
				t.Fatal(bad)
			}
		}
	}
	for _, m := range []int{0, 1501, 9001, 16001} {
		if _, e := VerifiedMTUScript(7, g, m); e == nil {
			t.Fatal(m)
		}
	}
	if _, e := VerifiedMTUScript(0, g, 9000); e == nil {
		t.Fatal("index")
	}
	if _, e := VerifiedMTUScript(7, "' injected", 9000); e == nil {
		t.Fatal("GUID")
	}
}
