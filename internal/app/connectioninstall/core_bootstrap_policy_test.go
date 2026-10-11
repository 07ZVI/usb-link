package connectioninstall

import (
	"testing"
	"time"
)

func TestCoreBootstrapRequiresFreshContinuousExactPair(t *testing.T) {
	base := time.Unix(100, 0)
	key := coreBootstrapIdentity{Job: "job", Hash: "hash", CandidatePID: 1, CorePID: 2, CandidateCreation: 3, CoreCreation: 4}
	var r coreBootstrapReadiness
	for i := 0; i < 30; i++ {
		if r.observe(base.Add(time.Duration(i)*time.Second), key, true) {
			t.Fatalf("ready early at %d", i)
		}
	}
	if !r.observe(base.Add(30*time.Second), key, true) {
		t.Fatal("continuous pair did not settle")
	}
	for name, changed := range map[string]coreBootstrapIdentity{
		"job":                 {Job: "new", Hash: "hash", CandidatePID: 1, CorePID: 2, CandidateCreation: 3, CoreCreation: 4},
		"hash":                {Job: "job", Hash: "changed", CandidatePID: 1, CorePID: 2, CandidateCreation: 3, CoreCreation: 4},
		"bootstrap_pid_reuse": {Job: "job", Hash: "hash", CandidatePID: 1, CorePID: 2, CandidateCreation: 5, CoreCreation: 4},
		"core_pid_reuse":      {Job: "job", Hash: "hash", CandidatePID: 1, CorePID: 2, CandidateCreation: 3, CoreCreation: 6},
		"core_replaced":       {Job: "job", Hash: "hash", CandidatePID: 1, CorePID: 7, CandidateCreation: 3, CoreCreation: 4},
	} {
		t.Run(name, func(t *testing.T) {
			copy := r
			if copy.observe(base.Add(31*time.Second), changed, true) {
				t.Fatal("replacement inherited readiness")
			}
		})
	}
	for name, at := range map[string]time.Time{"gap": base.Add(34 * time.Second), "clock_backwards": base.Add(29 * time.Second)} {
		t.Run(name, func(t *testing.T) {
			copy := r
			if copy.observe(at, key, true) {
				t.Fatal("stale interval inherited readiness")
			}
		})
	}
	if r.observe(base.Add(31*time.Second), key, false) || r.observe(base.Add(32*time.Second), key, true) {
		t.Fatal("unhealthy interval inherited readiness")
	}
}

func TestCoreFailedCandidateRequiresAttemptAndFailedStatus(t *testing.T) {
	for _, status := range []string{"rollback", "rollback_running", "rollback_failed", "failed"} {
		if !coreFailedCandidateRecorded(status, 1, 2) || coreFailedCandidateRecorded(status, 0, 2) || coreFailedCandidateRecorded(status, 1, 0) {
			t.Fatalf("invalid attempted-state gate %q", status)
		}
	}
	for _, status := range []string{"", "starting", "complete", "staged", "cancelled", "declined", "awaiting_local_approval", "deployed_recovery_required"} {
		if coreFailedCandidateRecorded(status, 1, 2) {
			t.Fatalf("unattempted/completed state fenced %q", status)
		}
	}
}
