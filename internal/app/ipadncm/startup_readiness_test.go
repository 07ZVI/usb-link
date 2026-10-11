package ipadncm

import "testing"

func TestStartupReadinessDoesNotEquateProblemZeroWithStarted(t *testing.T) {
	for _, e := range []startupReadiness{{Controls: 2, StartedControls: 2}, {Controls: 2, FailedControls: 2, OrphanData: 2, UngroupedRootConfirmed: true}} {
		if !e.settled() {
			t.Fatal("settled topology rejected", e)
		}
	}
	for _, e := range []startupReadiness{{Controls: 2}, {Controls: 2, StartedControls: 1}, {Controls: 1, StartedControls: 1}, {Controls: 2, FailedControls: 2}, {Controls: 2, FailedControls: 2, OrphanData: 1, UngroupedRootConfirmed: true}} {
		if e.settled() {
			t.Fatal("incomplete topology accepted", e)
		}
	}
}
