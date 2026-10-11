package remoteupdate

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func candidateFixture() (CandidateIdentity, CandidateStatusReceipt, time.Time) {
	now := time.Unix(1800000000, 0)
	id := CandidateIdentity{JobID: strings.Repeat("a", 32), Version: "0.8.103", SHA256: strings.Repeat("b", 64), PID: 31, Creation: 12345}
	receipt := CandidateStatusReceipt{Schema: 1, CandidateIdentity: id, ObservedUnixNano: now.Add(-time.Second).UnixNano(), Observation: CandidateStartupObservation{Phase: "preparation", Code: "USB_HOST_CLOSE_COMPLETION_PENDING"}}
	return id, receipt, now
}
func TestCandidateReceiptRequiresExactRecordedIdentityAndSameOSFreshness(t *testing.T) {
	id, r, now := candidateFixture()
	if !CandidateStatusMatches(r, id, now) {
		t.Fatal("exact fresh candidate rejected")
	}
	cases := map[string]func(*CandidateStatusReceipt){
		"job":           func(v *CandidateStatusReceipt) { v.JobID = strings.Repeat("c", 32) },
		"version":       func(v *CandidateStatusReceipt) { v.Version = "0.8.104" },
		"source":        func(v *CandidateStatusReceipt) { v.SHA256 = strings.Repeat("c", 64) },
		"pid":           func(v *CandidateStatusReceipt) { v.PID++ },
		"creation":      func(v *CandidateStatusReceipt) { v.Creation++ },
		"schema":        func(v *CandidateStatusReceipt) { v.Schema++ },
		"stale":         func(v *CandidateStatusReceipt) { v.ObservedUnixNano = now.Add(-11 * time.Second).UnixNano() },
		"future":        func(v *CandidateStatusReceipt) { v.ObservedUnixNano = now.Add(time.Second).UnixNano() },
		"raw code":      func(v *CandidateStatusReceipt) { v.Observation.Code = `C:\Users\secret\bad.log` },
		"raw phase":     func(v *CandidateStatusReceipt) { v.Observation.Phase = "account-name" },
		"unbound errno": func(v *CandidateStatusReceipt) { v.Observation.NativeError = 5 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if CandidateStatusMatches(bad, id, now) {
				t.Fatal("unmatched evidence accepted")
			}
			failure := RecordCandidateFailure(id, "HEALTH_TIMEOUT", bad, now)
			if failure.ReceiptObserved || failure.Code != "CANDIDATE_FAILURE_UNAVAILABLE" {
				t.Fatal("unmatched evidence attributed")
			}
		})
	}
}
func TestCandidateFailureSurvivesExitTimeoutAndRollbackTransitions(t *testing.T) {
	id, r, now := candidateFixture()
	for _, reason := range []string{"EXIT_BEFORE_HEALTH", "HEALTH_TIMEOUT"} {
		original := RecordCandidateFailure(id, reason, r, now)
		durable := original
		var statuses []string
		err := RunRollback("previous running", func(status, detail string) error {
			statuses = append(statuses, status)
			// Job save updates status/detail without replacing diagnostic identity.
			b, e := json.Marshal(struct {
				Status  string
				Failure CandidateFailure
			}{status, durable})
			if e != nil {
				return e
			}
			var saved struct {
				Status  string
				Failure CandidateFailure
			}
			if e = json.Unmarshal(b, &saved); e != nil {
				return e
			}
			durable = saved.Failure
			return nil
		}, func() RollbackResult {
			return RollbackResult{Status: "rollback_running", Detail: "previous verified core running"}
		})
		if err != nil || len(statuses) != 2 || statuses[0] != "rollback" || statuses[1] != "rollback_running" || durable != original {
			t.Fatalf("failure lost through rollback: %#v %v", statuses, err)
		}
		display := CandidateFailureDisplay(durable, id)
		if display["candidate_failure_reason"] != reason || display["candidate_failure_code"] != r.Observation.Code || display["candidate_failure_receipt_observed"] != "true" {
			t.Fatal(display)
		}
	}
}
func TestCandidateDiagnosticsAreNotReadinessAndUnknownsRemainUnknown(t *testing.T) {
	id, r, now := candidateFixture()
	failure := RecordCandidateFailure(id, "HEALTH_TIMEOUT", r, now)
	var tracker StartupTracker
	if got := tracker.Observe(now, StartupEvidence{Alive: true}, false); got != StartupWait {
		t.Fatal(got)
	}
	if CandidateFailureDisplay(CandidateFailure{}, id)["candidate_failure_reason"] != "" {
		t.Fatal("legacy empty field attributed")
	}
	mismatch := id
	mismatch.Creation++
	if len(CandidateFailureDisplay(failure, mismatch)) != 0 {
		t.Fatal("failure from another candidate shown")
	}
	if RecordCandidateFailure(id, "arbitrary cause", r, now) != (CandidateFailure{}) {
		t.Fatal("unknown reason guessed")
	}
	unknown := SanitizeCandidateStartup(CandidateStartupObservation{Phase: `private account`, Code: `C:\secret`, NativeError: 5})
	if unknown.Phase != "unavailable" || unknown.Code != "CANDIDATE_FAILURE_UNAVAILABLE" || unknown.NativeError != 0 {
		t.Fatal(unknown)
	}
	r.Observation = CandidateStartupObservation{Phase: "preparation", Code: "USB_HOST_NATIVE_OPERATION_FAILED", NativeError: 5}
	if RecordCandidateFailure(id, "HEALTH_TIMEOUT", r, now).NativeError != 5 {
		t.Fatal("fixed numeric errno lost")
	}
	prelaunch := id
	prelaunch.PID = 0
	prelaunch.Creation = 0
	failure = RecordCandidateFailure(prelaunch, "CANDIDATE_LAUNCH_FAILED", r, now)
	if failure.ReceiptObserved || CandidateFailureDisplay(failure, prelaunch)["candidate_failure_reason"] != "CANDIDATE_LAUNCH_FAILED" {
		t.Fatal("prelaunch error borrowed child evidence")
	}
	failure.Phase = "preparation"
	if len(CandidateFailureDisplay(failure, prelaunch)) != 0 {
		t.Fatal("unobserved field attributed")
	}
}
func TestCandidateReceiptStrictBoundedDuplicateFreeDecode(t *testing.T) {
	_, r, _ := candidateFixture()
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := DecodeCandidateStatus(b)
	if e != nil || decoded != r {
		t.Fatal(e)
	}
	cases := map[string]string{
		"top duplicate":      strings.Replace(string(b), `"schema":1`, `"schema":1,"schema":1`, 1),
		"identity duplicate": strings.Replace(string(b), `"pid":31`, `"pid":31,"pid":31`, 1),
		"nested duplicate":   strings.Replace(string(b), `"phase":"preparation"`, `"phase":"preparation","phase":"preparation"`, 1),
		"missing":            strings.Replace(string(b), `"schema":1,`, "", 1),
		"unknown":            strings.Replace(string(b), `"schema":1`, `"schema":1,"path":"secret"`, 1),
		"nested unknown":     strings.Replace(string(b), `"phase":"preparation"`, `"phase":"preparation","log":"secret"`, 1),
		"null":               strings.Replace(string(b), `"pid":31`, `"pid":null`, 1),
		"negative pid":       strings.Replace(string(b), `"pid":31`, `"pid":-1`, 1),
		"width":              strings.Replace(string(b), `"pid":31`, `"pid":4294967296`, 1),
		"trailing":           string(b) + "{}", "array": "[]", "large": strings.Repeat(" ", 4097),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeCandidateStatus([]byte(s)); e == nil {
				t.Fatal("malformed status accepted")
			}
		})
	}
}

func TestCandidateNativeStepFieldsAreOptionalStrictAndFixed(t *testing.T) {
	id, r, now := candidateFixture()
	// Schema1 original receipts still pass with both optional fields omitted.
	data, _ := json.Marshal(r)
	if old, e := DecodeCandidateStatus(data); e != nil || !CandidateStatusMatches(old, id, now) {
		t.Fatal("original schema1 receipt incompatible", e)
	}
	r.Observation = CandidateStartupObservation{Phase: "preparation", Code: "USB_HOST_NATIVE_STEP_FAILED", NativeOperation: "shared_host_firewall", NativeHRESULT: 0x80041008}
	data, _ = json.Marshal(r)
	decoded, e := DecodeCandidateStatus(data)
	if e != nil || !CandidateStatusMatches(decoded, id, now) {
		t.Fatal(e)
	}
	f := RecordCandidateFailure(id, "HEALTH_TIMEOUT", decoded, now)
	if f.NativeOperation != "shared_host_firewall" || f.NativeHRESULT != 0x80041008 || CandidateFailureDisplay(f, id)["candidate_failure_operation"] != "shared_host_firewall" {
		t.Fatal(f)
	}
	for _, change := range []func(*CandidateStartupObservation){
		func(v *CandidateStartupObservation) { v.NativeOperation = "private-path" },
		func(v *CandidateStartupObservation) { v.NativeHRESULT = 5 },
		func(v *CandidateStartupObservation) { v.NativeOperation = "" },
		func(v *CandidateStartupObservation) { v.Code = "USB_HOST_CLOSE_COMPLETION_PENDING" },
	} {
		bad := r
		change(&bad.Observation)
		if CandidateStatusMatches(bad, id, now) {
			t.Fatal("malformed native observation accepted", bad)
		}
	}
	duplicate := strings.Replace(string(data), `"native_hresult":2147749896`, `"native_hresult":2147749896,"native_hresult":2147749896`, 1)
	if duplicate == string(data) {
		t.Fatal("fixture wrong")
	}
	if _, e = DecodeCandidateStatus([]byte(duplicate)); e == nil {
		t.Fatal("optional duplicate accepted")
	}
}

func TestCandidateCanRetainFixedMacChildFailureWithoutBorrowingHostCause(t *testing.T) {
	id, r, now := candidateFixture()
	r.Observation = CandidateStartupObservation{Phase: "preparation", Code: "USB_HOST_NATIVE_STEP_FAILED", NativeOperation: "mac_address", NativeHRESULT: 0x80041008}
	f := RecordCandidateFailure(id, "HEALTH_TIMEOUT", r, now)
	if !f.ReceiptObserved || f.Phase != "preparation" || f.NativeOperation != "mac_address" || f.NativeHRESULT != 0x80041008 {
		t.Fatal(f)
	}
}

func TestCandidateResidentStagesRemainFixedAndStripUnboundNativeFields(t *testing.T) {
	for _, code := range []string{"USB_HOST_SOURCE_PIN_FAILED", "USB_HOST_RESIDENT_PREPARE_FAILED", "USB_HOST_RESIDENT_BATCH_FAILED", "USB_HOST_SOURCE_COMPLETE_FAILED"} {
		row := SanitizeCandidateStartup(CandidateStartupObservation{Phase: "preparation", Code: code, NativeOperation: "shared_host_firewall", NativeHRESULT: 0x80041008, NativeError: 5})
		if row.Code != code || row.NativeOperation != "" || row.NativeHRESULT != 0 || row.NativeError != 0 {
			t.Fatal(row)
		}
	}
}
