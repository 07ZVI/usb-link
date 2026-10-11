package usbaddress

import "testing"

func TestFixedProfilesAreDistinctAndUnknownCannotReachConfiguration(t *testing.T) {
	a, e := Lookup(Unified)
	if e != nil || a.Windows != "10.6.9.1" || a.Peer != "10.6.9.2" || a.Subnet != "10.6.9.0/24" {
		t.Fatal("unified profile mismatch")
	}
	b, e := Lookup(Legacy)
	if e != nil || b.Windows != "10.77.0.2" || b.Peer != "10.77.0.1" {
		t.Fatal("legacy profile lost")
	}
	if _, e = Lookup("unified;run-command"); e == nil {
		t.Fatal("untrusted address selector accepted")
	}
}
