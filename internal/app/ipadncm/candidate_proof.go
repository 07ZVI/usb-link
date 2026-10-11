package ipadncm

import (
	"strings"
	"sync"
)

// This gate contains only observed results from this process. Existing NCM,
// successful service changes, and imported logs cannot authorize a candidate.
type candidateModeProof struct {
	Root, State, Status                                               string
	ServiceState                                                      uint32
	Requested, Acknowledged, Reenumerated, NCM, USBIdentity, Restored bool
	Error, RestoreError                                               string
}

func (p candidateModeProof) valid() bool {
	wanted := uint32(4) // SERVICE_RUNNING, distinct from startup type.
	if p.State == "stopped" {
		wanted = 1
	} else if p.State != "running" {
		return false
	}
	root := strings.ToUpper(p.Root)
	return strings.HasPrefix(root, `USB\VID_05AC&PID_12AB\`) && len(root) > len(`USB\VID_05AC&PID_12AB\`) && len(root) <= 1024 && !strings.ContainsAny(root, "\x00\r\n") && p.ServiceState == wanted && p.Status == "NCM_DESCRIPTORS_AFTER_REQUEST" && p.Requested && p.Acknowledged && p.Reenumerated && p.NCM && p.USBIdentity && p.Restored && p.Error == "" && p.RestoreError == ""
}

type candidateProofGate struct {
	sync.Mutex
	proofs map[string]candidateModeProof
}

func (g *candidateProofGate) record(p candidateModeProof) {
	g.Lock()
	defer g.Unlock()
	if g.proofs == nil {
		g.proofs = make(map[string]candidateModeProof)
	}
	if p.State == "running" || p.State == "stopped" {
		g.proofs[p.State] = p
	}
}

func (g *candidateProofGate) scope() (string, bool) {
	g.Lock()
	defer g.Unlock()
	a, b := g.proofs["running"], g.proofs["stopped"]
	if !a.valid() || !b.valid() || !strings.EqualFold(a.Root, b.Root) {
		return "", false
	}
	return a.Root, true
}

func nextIPadCandidateStage(current, requested int) bool {
	if requested == 0 {
		return true
	}
	return current == 0 && requested == 3 || current == 3 && requested == 41 || current == 41 && requested == 42 || current == 42 && requested == 43 || current == 43 && requested == 5
}
