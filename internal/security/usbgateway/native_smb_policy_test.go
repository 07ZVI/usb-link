package usbgateway

import "testing"

func TestNativeSMBPolicyRejectsUnadmittedEndpointsAndForwarding(t *testing.T) {
	SetSharedHostLUID(42)
	defer SetSharedHostLUID(0)
	for _, tc := range []struct {
		LUID  uint64
		Peer  string
		Count int
	}{{42, "", 4}, {123, "10.6.9.2", 2}, {456, "10.6.9.3", 2}} {
		rows, e := NativeSMBPolicy(tc.LUID, tc.Peer)
		if e != nil || len(rows) != tc.Count {
			t.Fatal(rows, e)
		}
		for _, s := range rows {
			if e := validateNativeSMBSpec(s); e != nil {
				t.Fatal(e)
			}
			for _, mutate := range []func(*Specification){func(v *Specification) { v.Permit = false }, func(v *Specification) { v.LUID = 0 }, func(v *Specification) { v.NativeSMBPeer = "192.168.1.2" }, func(v *Specification) { v.Layer = forwardingLayers[0] }, func(v *Specification) { v.Application = "System" }, func(v *Specification) { v.HostServiceOnly = true }, func(v *Specification) { v.ForwardDestination = "10.6.9.1" }} {
				changed := s
				mutate(&changed)
				if validateNativeSMBSpec(changed) == nil {
					t.Fatal("scope widening accepted", changed)
				}
			}
		}
	}
	for _, p := range []string{"", "10.6.9.4", "127.0.0.1", "192.168.1.2"} {
		if _, e := NativeSMBPolicy(123, p); e == nil {
			t.Fatal("unadmitted peer", p)
		}
	}
}
