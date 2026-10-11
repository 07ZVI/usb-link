package remoteupdate

import (
	"encoding/json"
	"reflect"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"testing"
	"time"
)

func richFixture() CandidateRichReceipt {
	id, _, now := candidateFixture()
	return CandidateRichReceipt{Schema: 1, CandidateIdentity: id, ObservedUnixNano: now.UnixNano(), Observation: CandidateRichObservation{BridgePID: 41, BridgeCreation: 54321, BridgeSHA256: strings.Repeat("c", 64), Failure: netconfig.NativeStepDiagnostic{Schema: 1, Operation: "mac_resident_mac_plan", Code: "MAC_RESIDENT_MAC_PLAN_FAILED", CauseCode: "USB_RESIDENT_FOREIGN_SCOPE", CauseField: "MSFT_NetProtocolPortFilter/IcmpType"}}}
}
func anchorUnavailable() *netconfig.MacAnchorProjection {
	v := &netconfig.MacAnchorProjection{Schema: 1, ReadOnly: true}
	for i := 0; i < 5; i++ {
		v.Rows = append(v.Rows, netconfig.MacAnchorProjectionRow{SelectorIndex: i, Status: "unavailable", Fields: []netconfig.MacAnchorProjectionField{}})
	}
	return v
}
func TestRichHistoricalExactBindingAndNoLiveClock(t *testing.T) {
	r := richFixture()
	id := r.CandidateIdentity
	if !CandidateRichMatches(r, id) {
		t.Fatal("valid first failure rejected")
	}
	// It remains visible after exit/timeout/rollback, independent of the current
	// service PID and cross-machine wall clock. No readiness tracker consumes it.
	for _, status := range []string{"starting", "rollback", "rollback_running", "manual_recovery_required"} {
		if !CandidateRichMatches(r, id) {
			t.Fatal(status)
		}
	}
	r.ObservedUnixNano = time.Unix(1, 0).UnixNano()
	if !CandidateRichMatches(r, id) {
		t.Fatal("historical evidence treated as liveness")
	}
	for _, change := range []func(*CandidateIdentity){func(x *CandidateIdentity) { x.JobID = strings.Repeat("d", 32) }, func(x *CandidateIdentity) { x.Version = "0.8.117" }, func(x *CandidateIdentity) { x.SHA256 = strings.Repeat("d", 64) }, func(x *CandidateIdentity) { x.PID++ }, func(x *CandidateIdentity) { x.Creation++ }} {
		bad := id
		change(&bad)
		if CandidateRichMatches(r, bad) {
			t.Fatal("foreign candidate shown")
		}
	}
	var tracker StartupTracker
	if tracker.Observe(time.Now(), StartupEvidence{Alive: true}, false) != StartupWait {
		t.Fatal("diagnostic promoted to readiness")
	}
}
func TestRichStrictNestedDecodeAndOriginalWorkerCompatibility(t *testing.T) {
	r := richFixture()
	r.Observation.AnchorProjection = anchorUnavailable()
	r.Observation.DiagnosticTiming = &netconfig.BridgeNetworkScriptTiming{Operation: "diagnostic", Count: 1, DurationMS: 3333, Success: true}
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := DecodeCandidateRich(b)
	if e != nil || !reflect.DeepEqual(r, decoded) {
		t.Fatal(e)
	}
	cases := map[string]string{
		"duplicate_identity":     strings.Replace(string(b), `"pid":31`, `"pid":31,"pid":31`, 1),
		"unknown":                strings.Replace(string(b), `"schema":1`, `"schema":1,"path":"secret"`, 1),
		"missing":                strings.Replace(string(b), `"bridge_pid":41,`, "", 1),
		"null":                   strings.Replace(string(b), `"bridge_pid":41`, `"bridge_pid":null`, 1),
		"same_parent":            strings.Replace(string(b), `"bridge_pid":41`, `"bridge_pid":31`, 1),
		"unknown_cause":          strings.Replace(string(b), `USB_RESIDENT_FOREIGN_SCOPE`, `a-secret-path`, 1),
		"unknown_field":          strings.Replace(string(b), `MSFT_NetProtocolPortFilter/IcmpType`, `device-instance`, 1),
		"child_duplicate":        strings.Replace(string(b), `"bridge_pid":41`, `"bridge_pid":41,"bridge_pid":41`, 1),
		"failure_duplicate":      strings.Replace(string(b), `"cause_code":"USB_RESIDENT_FOREIGN_SCOPE"`, `"cause_code":"USB_RESIDENT_FOREIGN_SCOPE","cause_code":"USB_RESIDENT_FOREIGN_SCOPE"`, 1),
		"projection_duplicate":   strings.Replace(string(b), `"read_only":true`, `"read_only":true,"read_only":true`, 1),
		"wrong_projection_cause": strings.Replace(string(b), `USB_RESIDENT_FOREIGN_SCOPE`, `USB_NATIVE_FIREWALL_CONSTRAINT_NULL`, 1),
		"timing_duplicate":       strings.Replace(string(b), `"count":1`, `"count":1,"count":1`, 1),
		"non_diagnostic_time":    strings.Replace(string(b), `"operation":"diagnostic"`, `"operation":"cleanup"`, 1),
		"trailing":               string(b) + `{}`, "oversize": strings.Repeat(" ", CandidateRichByteLimit+1),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeCandidateRich([]byte(s)); e == nil {
				t.Fatal("malformed diagnostic accepted")
			}
		})
	}
	_, legacy, _ := candidateFixture()
	lb, _ := json.Marshal(legacy)
	if _, e := DecodeCandidateStatus(lb); e != nil {
		t.Fatal("old schema changed", e)
	}
	if _, e := DecodeCandidateStatus(b); e == nil {
		t.Fatal("rich schema accidentally admitted by old worker")
	}
}
func TestRichFirstCauseOnlyEnrichmentAndDeepCopy(t *testing.T) {
	old := richFixture()
	next := old
	next.ObservedUnixNano++
	next.Observation.AnchorProjection = anchorUnavailable()
	next.Observation.DiagnosticTiming = &netconfig.BridgeNetworkScriptTiming{Operation: "diagnostic", Count: 1, DurationMS: 5, Success: false}
	merged, e := MergeCandidateRich(old, next)
	if e != nil || merged.Observation.AnchorProjection == nil {
		t.Fatal(e)
	}
	next.Observation.AnchorProjection.Rows[0].SelectorIndex = 9
	if merged.Observation.AnchorProjection.Rows[0].SelectorIndex != 0 {
		t.Fatal("copy aliases producer")
	}
	later := old
	later.ObservedUnixNano += 2
	kept, e := MergeCandidateRich(merged, later)
	if e != nil || kept.Observation.DiagnosticTiming == nil || kept.Observation.AnchorProjection == nil {
		t.Fatal("enrichment erased", e)
	}
	for name, change := range map[string]func(*CandidateRichReceipt){
		"childPID": func(x *CandidateRichReceipt) { x.Observation.BridgePID++ }, "creation": func(x *CandidateRichReceipt) { x.Observation.BridgeCreation++ }, "source": func(x *CandidateRichReceipt) { x.Observation.BridgeSHA256 = strings.Repeat("d", 64) }, "cause": func(x *CandidateRichReceipt) {
			x.Observation.Failure.CauseField = "MSFT_NetProtocolPortFilter/Protocol"
		}, "backwards": func(x *CandidateRichReceipt) { x.ObservedUnixNano-- }, "later_cleanup": func(x *CandidateRichReceipt) {
			x.Observation.Failure = netconfig.NativeStepDiagnostic{Schema: 1, Operation: "cleanup"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := old
			change(&v)
			if _, e := MergeCandidateRich(old, v); e == nil {
				t.Fatal("first failure overwritten")
			}
		})
	}
	drift := kept
	row := *kept.Observation.DiagnosticTiming
	row.DurationMS++
	drift.Observation.DiagnosticTiming = &row
	if _, e := MergeCandidateRich(kept, drift); e == nil {
		t.Fatal("observed timing overwritten")
	}
	malformed := CandidateRichReceipt{ObservedUnixNano: 1}
	if _, e := MergeCandidateRich(malformed, old); e == nil {
		t.Fatal("malformed previous receipt treated as absent")
	}
}
func TestRichProjectionDoesNotBroadenExistingValidation(t *testing.T) {
	r := richFixture()
	r.Observation.NullProjection = &netconfig.MacNullProjection{Schema: 1, ReadOnly: true}
	if CandidateRichObservationValid(&r.Observation) {
		t.Fatal("wrong/missing projection accepted")
	}
	r.Observation.NullProjection = nil
	r.Observation.AnchorProjection = anchorUnavailable()
	r.Observation.AnchorProjection.Rows = append(r.Observation.AnchorProjection.Rows, r.Observation.AnchorProjection.Rows[0])
	if CandidateRichObservationValid(&r.Observation) {
		t.Fatal("extra selector accepted")
	}
	r = richFixture()
	r.Observation.BridgeSHA256 = "C:\\secret.exe"
	if CopyCandidateRichObservation(&r.Observation) != nil {
		t.Fatal("raw source path accepted")
	}
}

func TestRichActualSecondaryCleanupPreservesPlanCause(t *testing.T) {
	first := richFixture()
	next := first
	next.ObservedUnixNano++
	next.Observation.CleanupFailure = &CandidateCleanupFailure{Phase: "parent_recover", Code: "MAC_RESIDENT_ADAPTER_ABSENCE_UNPROVEN", CleanupConfirmed: false}
	kept, e := MergeCandidateRich(first, next)
	if e != nil || kept.Observation.Failure != first.Observation.Failure || kept.Observation.CleanupFailure == nil {
		t.Fatal("actual cleanup lost first cause", e)
	}
	b, _ := json.Marshal(kept)
	decoded, e := DecodeCandidateRich(b)
	if e != nil || !reflect.DeepEqual(kept, decoded) {
		t.Fatal("secondary did not survive persistence", e)
	}
	for name, s := range map[string]string{
		"success":        strings.Replace(string(b), `"cleanup_confirmed":false`, `"cleanup_confirmed":true`, 1),
		"missing_false":  strings.Replace(string(b), `,"cleanup_confirmed":false`, "", 1),
		"null_false":     strings.Replace(string(b), `"cleanup_confirmed":false`, `"cleanup_confirmed":null`, 1),
		"unknown_code":   strings.Replace(string(b), `MAC_RESIDENT_ADAPTER_ABSENCE_UNPROVEN`, `C:\\private-file`, 1),
		"unknown_phase":  strings.Replace(string(b), `parent_recover`, `guess_exit`, 1),
		"extra_exitcode": strings.Replace(string(b), `"cleanup_confirmed":false`, `"cleanup_confirmed":false,"exit_code":9`, 1),
		"duplicate":      strings.Replace(string(b), `"cleanup_confirmed":false`, `"cleanup_confirmed":false,"cleanup_confirmed":false`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeCandidateRich([]byte(s)); e == nil {
				t.Fatal("unproven cleanup accepted")
			}
		})
	}
	missing := first
	missing.ObservedUnixNano += 2
	survived, e := MergeCandidateRich(kept, missing)
	if e != nil || survived.Observation.CleanupFailure == nil {
		t.Fatal("later nil erased observed cleanup", e)
	}
	drift := kept
	row := *kept.Observation.CleanupFailure
	row.Code = "MAC_BRIDGE_STILL_RUNNING"
	drift.Observation.CleanupFailure = &row
	if _, e := MergeCandidateRich(kept, drift); e == nil {
		t.Fatal("actual secondary replaced")
	}
	next.Observation.CleanupFailure.Code = "MAC_BRIDGE_STILL_RUNNING"
	if kept.Observation.CleanupFailure.Code != "MAC_RESIDENT_ADAPTER_ABSENCE_UNPROVEN" {
		t.Fatal("secondary aliases producer")
	}
}
