package updater

import (
	"strings"
	"testing"
)

func TestUpdateOutcomeRequiresVersionAndReportedUSBReadiness(t *testing.T) {
	for _, tc := range []struct {
		status, version, usb, deployment string
		done, failed                     bool
	}{
		{"complete", "0.8.74", "", "", true, false},
		{"complete", "0.8.74", "verified", "installed", true, false},
		{"complete", "0.8.73", "verified", "installed", false, true},
		{"complete", "0.8.74", "recovery_required", "installed", false, true},
		{"complete", "0.8.74", "verified", "pending", false, true},
		{"deployed_recovery_required", "0.8.74", "recovery_required", "installed", false, true},
		{"deployed_not_running", "0.8.73", "verified", "installed", false, true},
		{"rollback_running", "0.8.73", "", "", false, true},
		{"rollback_failed", "0.8.73", "", "", false, true},
		{"manual_recovery_required", "0.8.74", "", "", false, true},
		{"cancelled", "0.8.73", "", "", false, true},
		{"starting", "0.8.74", "", "", false, false},
	} {
		t.Run(tc.status+tc.version+tc.usb+tc.deployment, func(t *testing.T) {
			var s updateObservation
			s.Version = tc.version
			s.Update.Status, s.Update.USB, s.Update.Deployment = tc.status, tc.usb, tc.deployment
			done, err := classifyUpdateOutcome(s, "0.8.74")
			if done != tc.done || (err != nil) != tc.failed {
				t.Fatalf("done=%v err=%v", done, err)
			}
		})
	}
}

func TestCancellationCannotChooseOtherJobsOrCancelExecutingJob(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	valid := []byte(`{"update":{"ID":"` + id + `","Status":"staged"}}`)
	payload, got, err := ownedCancellationPayload(valid)
	if err != nil || got != id || string(payload) != `{"id":"`+id+`"}` {
		t.Fatal(got, string(payload), err)
	}
	for _, b := range []string{`{}`, `{"update":{"ID":"../../job","Status":"staged"}}`, `{"update":{"ID":"` + id + `","Status":"handoff"}}`, `{"update":{"ID":"0123456789ABCDEF0123456789ABCDEF","Status":"staged"}}`} {
		if _, _, err = ownedCancellationPayload([]byte(b)); err == nil {
			t.Fatal("unexpected cancellation:", b)
		}
	}
	for _, b := range []string{`{}`, `{"id":"another","status":"cancelled"}`, `{"id":"` + id + `","status":"starting"}`} {
		if verifyCancellationAck([]byte(b), id) == nil {
			t.Fatal("unexpected confirmation:", b)
		}
	}
	if err = verifyCancellationAck([]byte(`{"id":"`+id+`","status":"cancelled"}`), id); err != nil {
		t.Fatal(err)
	}
}

func TestPersistenceRecoveryCancellationRequiresExactRetainedStatus(t *testing.T) {
	id := strings.Repeat("a", 32)
	good := `{"update":{"id":"` + id + `","status":"persistence_recovery_required","persistence_retry":"true","retry_job_id":"` + id + `"}}`
	if _, got, err := ownedCancellationPayload([]byte(good)); err != nil || got != id {
		t.Fatal(got, err)
	}
	for _, body := range []string{strings.ReplaceAll(good, `"persistence_retry":"true"`, `"persistence_retry":"false"`), strings.ReplaceAll(good, `"retry_job_id":"`+id+`"`, `"retry_job_id":"`+strings.Repeat("b", 32)+`"`)} {
		if _, _, err := ownedCancellationPayload([]byte(body)); err == nil {
			t.Fatal("ambiguous repair accepted")
		}
	}
	if err := verifyCancellationAck([]byte(`{"id":"`+id+`","status":"persistence_recovered"}`), id); err != nil {
		t.Fatal(err)
	}
}
