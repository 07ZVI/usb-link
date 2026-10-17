package ipadncm

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestLocalTrustTrialReadOnlyFailureReleasesOnlyWithoutRecoveryObligation(t *testing.T) {
	for _, code := range []string{"DIAGNOSTIC_CANCELLED_BEFORE_CHANGE", "SERVICE_MANAGER_UNAVAILABLE", "OFFICIAL_APPLE_SERVICE_NOT_FOUND", "INITIAL_SERVICE_STATE_NOT_STABLE"} {
		for _, tc := range []struct {
			name             string
			journalAttempted bool
			readError        error
			want             bool
		}{
			{"absent", false, os.ErrNotExist, true},
			{"existing", false, nil, false},
			{"unreadable", false, os.ErrPermission, false},
			{"invalid", false, errors.New("invalid receipt"), false},
			{"write_interrupted_even_if_absent", true, os.ErrNotExist, false},
		} {
			t.Run(code+"/"+tc.name, func(t *testing.T) {
				reads := 0
				proof := localTrustTrialNoChangeProof(tc.journalAttempted, code, func() error { reads++; return tc.readError })
				if proof != tc.want || localTrustTrialSafeNoChange(true, code, proof) != tc.want || localTrustTrialSafeNoChange(false, code, proof) {
					t.Fatalf("unsafe resume decision: proof=%v", proof)
				}
				if tc.journalAttempted && reads != 0 {
					t.Fatal("attempted journal write was reconsidered using later file absence")
				}
			})
		}
	}
	for _, code := range []string{"", "SERVICE_RESTORE_JOURNAL_UNAVAILABLE", "SERVICE_TEST_STATE_UNAVAILABLE", "SERVICE_STATE_CHANGED_DURING_TEST", "SERVICE_STATE_RESTORE_FAILED"} {
		proof := localTrustTrialNoChangeProof(false, code, func() error { t.Fatal("post-change result checked absence"); return os.ErrNotExist })
		if proof || localTrustTrialSafeNoChange(true, code, true) {
			t.Fatalf("post-change error %s allowed no-change release", code)
		}
	}
}

func TestLocalTrustTrialRequiresCleanupAndCompleteRecovery(t *testing.T) {
	for _, tc := range []struct {
		safe, restored bool
		problem        string
		want           bool
	}{
		{true, true, "", true},
		{false, true, "", false},
		{true, false, "", false},
		{true, true, "SERVICE_RESTORE_JOURNAL_REMOVE_FAILED", false},
		{true, false, "SERVICE_STATE_RESTORE_FAILED", false},
	} {
		if got := localTrustTrialCanResume(tc.safe, tc.restored, tc.problem); got != tc.want {
			t.Fatalf("%+v resume=%v", tc, got)
		}
		if got := localTrustTrialCompletion(tc.safe, tc.restored, tc.problem); (got == "complete_restored") != tc.want {
			t.Fatalf("%+v phase=%s", tc, got)
		}
	}
}

func TestLocalTrustTrialEarlyCancellationCannotBypassRecovery(t *testing.T) {
	for _, tc := range []struct {
		safe, absent bool
		code         string
		want         bool
	}{
		{true, true, "DIAGNOSTIC_CANCELLED_BEFORE_CHANGE", true},
		{false, true, "DIAGNOSTIC_CANCELLED_BEFORE_CHANGE", false},
		{true, false, "DIAGNOSTIC_CANCELLED_BEFORE_CHANGE", false},
		{true, true, "SERVICE_STATE_RESTORE_FAILED", false},
		{true, true, "", false},
	} {
		if got := localTrustTrialSafeEarlyCancel(tc.safe, tc.code, tc.absent); got != tc.want {
			t.Fatalf("%+v resume=%v", tc, got)
		}
	}
}

func TestLocalTrustTrialCompactStatusBound(t *testing.T) {
	s := LocalTrustServiceTrial{Requested: true, Running: true, Phase: "cancelling_and_restoring", Error: strings.Repeat("E", 80), RestoreError: strings.Repeat("E", 80), Before: 4, During: 1, After: 4, StartType: 2, AttemptBefore: ^uint64(0), AttemptAfter: ^uint64(0)}
	b, err := json.Marshal(s)
	if err != nil || len(b) > 600 {
		t.Fatalf("bytes=%d error=%v", len(b), err)
	}
}

func TestLocalTrustTrialRetainsServiceRestoreAndAdmissionBoundary(t *testing.T) {
	b, err := os.ReadFile("amds_mode_diagnostic_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, need := range []string{`buildinfo.LocalDiagnostics != "true"`, `startAMDSModeDiagnostic(ctx, version, "stopped", true)`, `budget = 110 * time.Second`, `context.WithTimeout(jobCtx, budget)`, `defer SetConnectionContext(ctx)`, `context.WithTimeout(context.Background(), 10*time.Second)`, `saveAMDSDiagnosticJournal(dir, r.Before, r.OriginalStartType)`, `localTrustTrialCanResume(cleanupSafe, r.Restored, r.RestoreError)`, `cfg.StartType == config.StartType`, `diagnosticServiceState(restoreCtx, s, status.State)`} {
		if !strings.Contains(s, need) {
			t.Errorf("missing %s", need)
		}
	}
	for _, forbidden := range []string{`UpdateConfig(`, `ChangeServiceConfig`, `queryModel(`, `StartSession(`} {
		if strings.Contains(s, forbidden) {
			t.Errorf("unexpected %s", forbidden)
		}
	}
	launcher, err := os.ReadFile("../launcher/main_windows.go")
	if err != nil || !strings.Contains(string(launcher), `RunPendingAMDSModeDiagnostic(ctx, version, dir, safe)`) {
		t.Fatal("pending job not dispatched")
	}
	migration, err := os.ReadFile("simplified_network_windows.go")
	if err != nil || !strings.Contains(string(migration), `RecoverAMDSModeDiagnostic(dir)`) || !strings.Contains(string(migration), `"amds-diagnostic.json"`) {
		t.Fatal("startup restoration path missing")
	}
}
