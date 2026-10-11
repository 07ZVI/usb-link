package ipadncm

import "testing"

func proof(state, root string) candidateModeProof {
	s := uint32(4)
	if state == "stopped" {
		s = 1
	}
	return candidateModeProof{Root: root, State: state, Status: "NCM_DESCRIPTORS_AFTER_REQUEST", ServiceState: s, Requested: true, Acknowledged: true, Reenumerated: true, NCM: true, USBIdentity: true, Restored: true}
}

func TestCandidateRequiresBothActualSwitchesOnSameDevice(t *testing.T) {
	root := `USB\VID_05AC&PID_12AB\1234`
	var g candidateProofGate
	g.record(proof("running", root))
	if _, ok := g.scope(); ok {
		t.Fatal("one mode is insufficient")
	}
	g.record(proof("stopped", root+"5"))
	if _, ok := g.scope(); ok {
		t.Fatal("mixed devices")
	}
	g.record(proof("stopped", root))
	if scope, ok := g.scope(); !ok || scope != root {
		t.Fatal("two observed switches rejected")
	}
	p := proof("stopped", root)
	p.Status = "NCM_DESCRIPTORS_PRESENT"
	g.record(p)
	if _, ok := g.scope(); ok {
		t.Fatal("a later no-op must invalidate proof")
	}
}

func TestCandidateRejectsUnobservedServiceAndIncompleteRestoration(t *testing.T) {
	base := proof("running", `USB\VID_05AC&PID_12AB\1234`)
	for _, alter := range []func(*candidateModeProof){func(p *candidateModeProof) { p.ServiceState = 1 }, func(p *candidateModeProof) { p.Requested = false }, func(p *candidateModeProof) { p.Acknowledged = false }, func(p *candidateModeProof) { p.Reenumerated = false }, func(p *candidateModeProof) { p.NCM = false }, func(p *candidateModeProof) { p.USBIdentity = false }, func(p *candidateModeProof) { p.Restored = false }, func(p *candidateModeProof) { p.RestoreError = "failed" }, func(p *candidateModeProof) { p.Error = "changed" }, func(p *candidateModeProof) { p.Root = `USB\VID_05AC&PID_12AB\` }} {
		p := base
		alter(&p)
		if p.valid() {
			t.Fatalf("invalid proof accepted: %+v", p)
		}
	}
}

func TestCandidateStageCannotSkipOrMoveBackwardWithoutReset(t *testing.T) {
	for _, p := range [][2]int{{0, 3}, {3, 41}, {41, 42}, {42, 43}, {43, 5}, {5, 0}, {42, 0}} {
		if !nextIPadCandidateStage(p[0], p[1]) {
			t.Fatal(p)
		}
	}
	for _, p := range [][2]int{{0, 5}, {0, 41}, {3, 43}, {41, 3}, {43, 4}, {5, 43}, {0, -1}} {
		if nextIPadCandidateStage(p[0], p[1]) {
			t.Fatal(p)
		}
	}
}
