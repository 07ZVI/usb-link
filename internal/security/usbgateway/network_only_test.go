package usbgateway

import "testing"

func TestNetworkOnlyRestrictionsStayOnIPadAndNeverGrant(t *testing.T) {
	specs, e := IPadNetworkOnlyPolicy(30, 10, []string{`C:\Program Files\iTunes\iTunes.exe`, `C:\Games\sunshine.exe`})
	if e != nil {
		t.Fatal(e)
	}
	seen62078, seenMDNS, seenApple := false, false, false
	for _, s := range specs {
		if e := validateNetworkOnlySpec(s); e != nil {
			t.Fatal(e, s)
		}
		if s.Permit || s.LUID != 30 && (s.LUID != 10 || s.NetworkOnlyPeer != "10.6.9.3") {
			t.Fatal("scope widened", s)
		}
		if s.LUID == 10 && s.NetworkOnlyPort == 5353 {
			t.Fatal("Mac shared-host discovery affected", s)
		}
		seen62078 = seen62078 || s.NetworkOnlyPort == 62078
		seenMDNS = seenMDNS || s.NetworkOnlyPort == 5353
		seenApple = seenApple || s.Application != ""
	}
	if !seen62078 || !seenMDNS || !seenApple {
		t.Fatal("missing restriction")
	}
	bad := specs[0]
	bad.Permit = true
	if validateNetworkOnlySpec(bad) == nil {
		t.Fatal("permit accepted")
	}
	bad = specs[0]
	bad.NetworkOnlyPeer = "10.6.9.2"
	if validateNetworkOnlySpec(bad) == nil {
		t.Fatal("Mac target accepted")
	}
	if _, e := IPadNetworkOnlyPolicy(10, 10, nil); e == nil {
		t.Fatal("shared host used as physical iPad")
	}
	if appleSyncApplication(`C:\Games\sunshine.exe`) || !appleSyncApplication(`C:\Apps\AppleMobileDeviceProcess.exe`) {
		t.Fatal("process family matching")
	}
}
