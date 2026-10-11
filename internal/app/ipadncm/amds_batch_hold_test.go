package ipadncm

import (
	"sync"
	"testing"
)

func TestAMDSBatchKeepsOrdinaryConnectionHeldBetweenProbes(t *testing.T) {
	var g amdsDiagnosticBatchGate
	if g.holding() {
		t.Fatal("legacy default must allow ordinary connections")
	}
	g.hold()
	// Receiving probe completion or cancellation does not verify recovery.
	for i := 0; i < 2; i++ {
		if g.release(false, false) || !g.holding() {
			t.Fatal("probe completion or cancellation released the batch")
		}
	}
	if g.release(true, true) || !g.holding() {
		t.Fatal("an active second probe was released")
	}
	if !g.release(true, false) || g.holding() {
		t.Fatal("verified safe stage-3/recovery must release the batch")
	}
}
func TestAMDSBatchFailedRecoveryDoesNotReleaseRearmedBatch(t *testing.T) {
	var g amdsDiagnosticBatchGate
	g.hold()
	if !g.release(true, false) {
		t.Fatal("verified recovery refused")
	}
	g.hold()
	if g.release(false, false) || !g.holding() {
		t.Fatal("failed recovery released the rearmed batch")
	}
}
func TestAMDSBatchConcurrentStatusAndFailedRecovery(t *testing.T) {
	var g amdsDiagnosticBatchGate
	g.hold()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				g.holding()
				g.release(false, false)
			}
		}()
	}
	wg.Wait()
	if !g.holding() {
		t.Fatal("status observation released the batch")
	}
}
