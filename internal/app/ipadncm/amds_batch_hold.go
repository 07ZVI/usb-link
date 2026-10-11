package ipadncm

import "sync"

// A diagnostic batch owns only permission for ordinary iPad auto-connection.
// Completing one probe or canceling it does not end that ownership. No driver,
// service, pairing, or independent Mac state is represented by this gate.
type amdsDiagnosticBatchGate struct {
	sync.Mutex
	held bool
}

func (g *amdsDiagnosticBatchGate) hold() {
	g.Lock()
	g.held = true
	g.Unlock()
}
func (g *amdsDiagnosticBatchGate) holding() bool {
	g.Lock()
	defer g.Unlock()
	return g.held
}
func (g *amdsDiagnosticBatchGate) release(verified, active bool) bool {
	g.Lock()
	defer g.Unlock()
	if !verified || active {
		return false
	}
	g.held = false
	return true
}

var amdsDiagnosticBatch amdsDiagnosticBatchGate

func IPadModeDiagnosticHeld() bool { return amdsDiagnosticBatch.holding() }
