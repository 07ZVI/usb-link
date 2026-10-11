package usbgateway

import "testing"

func TestDiagnosticEchoScopeRejectsWidening(t *testing.T) {
	specs, e := DiagnosticICMPPolicy(42)
	if e != nil || len(specs) != 2 {
		t.Fatal(e)
	}
	for _, s := range specs {
		if e = validateDiagnosticICMPSpec(s); e != nil {
			t.Fatal(e)
		}
		for _, change := range []func(*Specification){func(s *Specification) { s.LUID = 0 }, func(s *Specification) { s.Permit = false }, func(s *Specification) { s.Application = "System" }, func(s *Specification) { s.NativeSMBPeer = "10.6.9.3" }, func(s *Specification) { s.Layer = applicationLayers[2] }, func(s *Specification) { s.ForwardSource = "10.6.9.2" }, func(s *Specification) { s.DiagnosticICMP = "all" }, func(s *Specification) { s.HostServiceOnly = true }} {
			bad := s
			change(&bad)
			if validateDiagnosticICMPSpec(bad) == nil {
				t.Fatal("widened diagnostic scope accepted", bad)
			}
		}
	}
}
