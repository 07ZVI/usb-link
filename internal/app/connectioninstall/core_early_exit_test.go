package connectioninstall

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCoreEarlyExitMatching(t *testing.T) {
	began := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	r := newCoreEarlyExit("0.10.62", 7, began.Add(-30*time.Second), "CORE_ACTIVATION_FAILED", errors.New("CORE_SERVICE_SOURCE_CHANGED"))
	if !matchCoreEarlyExit(r, "0.10.62", began) {
		t.Fatal("record within slack must match")
	}
	if matchCoreEarlyExit(r, "0.10.55", began) {
		t.Fatal("other version must not match")
	}
	old := newCoreEarlyExit("0.10.62", 7, began.Add(-2*time.Minute), "x", nil)
	if matchCoreEarlyExit(old, "0.10.62", began) || matchCoreEarlyExit(CoreEarlyExit{Version: "0.10.62", UTC: "bad"}, "0.10.62", began) {
		t.Fatal("stale or unparsable record must not match")
	}
}

func TestCoreEarlyExitBounded(t *testing.T) {
	r := newCoreEarlyExit("v", 1, time.Now(), "s\n", errors.New(strings.Repeat("eé", 500)))
	if len(r.Error) != 400 || strings.ContainsAny(r.Stage, "\n") || strings.ContainsRune(r.Error, 'é') {
		t.Fatalf("not bounded ASCII: %q %q", r.Stage, r.Error)
	}
}

func TestStartEvidenceFormatting(t *testing.T) {
	began := time.Now()
	cause := errors.New("start_service: timeout")
	early := newCoreEarlyExit("0.10.62", 9, began, "CORE_ACTIVATION_FAILED", errors.New("CORE_SERVICE_SOURCE_CHANGED"))
	got := withStartEvidence(cause, &coreServiceExit{State: 1, Win32: 1053}, &early, "0.10.62", began)
	for _, want := range []string{"start_service: timeout", "scm_state=1 win32=1053 exit=0", "core_early_exit stage=CORE_ACTIVATION_FAILED error=CORE_SERVICE_SOURCE_CHANGED"} {
		if !strings.Contains(got.Error(), want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
	if !errors.Is(got, cause) {
		t.Fatal("cause lost")
	}
	stale := withStartEvidence(cause, nil, &early, "0.10.55", began)
	if strings.Contains(stale.Error(), "core_early_exit") || !strings.Contains(stale.Error(), "scm_status=unknown") {
		t.Fatalf("unexpected: %v", stale)
	}
	if withStartEvidence(nil, nil, nil, "", began) != nil {
		t.Fatal("nil must stay nil")
	}
}

func TestInstallStepError(t *testing.T) {
	cause := errors.New("boom")
	got := installStepError("START", cause)
	if !strings.HasPrefix(got.Error(), "INSTALL_START_FAILED: ") || !errors.Is(got, cause) {
		t.Fatalf("got %v", got)
	}
	if installStepError("START", nil) != nil || installStepError("START", context.Canceled) != context.Canceled {
		t.Fatal("nil and cancellation must pass through")
	}
}
