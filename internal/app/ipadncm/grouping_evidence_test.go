package ipadncm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGroupingEvidenceExplainsEachExistingPredicate(t *testing.T) {
	good := groupingEligibilityInput{RootFound: true, DriverVersion: "486.0.0.0", EnumeratorError: "WIN32_2", FailedControls: 2, UnboundData: 2}
	if got := describeGroupingEligibility(good); len(got.FailedConditions) != 0 || !got.EnumeratorAbsent || !got.RootStateReadable {
		t.Fatal("qualified topology misdescribed", got)
	}
	for _, tc := range []struct {
		name, want string
		change     func(*groupingEligibilityInput)
	}{
		{"missing_root", "USBCCGP_ROOT_NOT_FOUND", func(i *groupingEligibilityInput) { i.RootFound = false }},
		{"root_problem", "ROOT_HAS_PROBLEM", func(i *groupingEligibilityInput) { i.RootProblem = 10 }},
		{"unreadable", "ROOT_STATE_UNREADABLE", func(i *groupingEligibilityInput) { i.RootStateError = "private error" }},
		{"version", "ROOT_DRIVER_VERSION_MISMATCH", func(i *groupingEligibilityInput) { i.DriverVersion = "487.0.0.0" }},
		{"enumerator", "ENUMERATOR_CLASS_NOT_VERIFIED_ABSENT", func(i *groupingEligibilityInput) { i.EnumeratorError = ""; i.EnumeratorClass = "020000" }},
		{"controls", "EXPECTED_TWO_FAILED_NCM_CONTROLS", func(i *groupingEligibilityInput) { i.FailedControls = 1 }},
		{"data", "EXPECTED_TWO_UNBOUND_DATA_NODES", func(i *groupingEligibilityInput) { i.UnboundData = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := good
			tc.change(&in)
			got := describeGroupingEligibility(in)
			if len(got.FailedConditions) != 1 || got.FailedConditions[0] != tc.want {
				t.Fatal(got)
			}
		})
	}
}

func TestGroupingEvidenceCacheCopiesAndDoesNotExportNativeText(t *testing.T) {
	groupingEvidenceCache.Lock()
	previous := groupingEvidenceCache.latest
	groupingEvidenceCache.Unlock()
	t.Cleanup(func() {
		groupingEvidenceCache.Lock()
		groupingEvidenceCache.latest = previous
		groupingEvidenceCache.Unlock()
	})
	in := groupingEligibilityInput{RootFound: true, DriverVersion: "PRIVATE_PATH", RootStateError: "PRIVATE_ERROR", EnumeratorError: "PRIVATE_ERROR", EnumeratorClass: "PRIVATE_VALUE"}
	d := describeGroupingEligibility(in)
	d.Attempt = 9
	recordGroupingEligibility(d, "DIAGNOSED_UNGROUPED_NATIVE_FAILURE_REQUIRED")
	d.FailedConditions[0] = "PRIVATE_MUTATION"
	got := latestGroupingEligibility()
	if got.Attempt != 9 || !got.TopologyChecked || got.EnumeratorState != "read_failed" {
		t.Fatal(got)
	}
	got.FailedConditions[0] = "PRIVATE_MUTATION"
	body, _ := json.Marshal(latestGroupingEligibility())
	if strings.Contains(string(body), "PRIVATE") {
		t.Fatal("private native text or aliased cache escaped")
	}
	recordGroupingEligibility(groupingEligibilityEvidence{Attempt: 10}, "TARGET_CHANGED_OR_NCM_NOT_ACTIVE")
	if got = latestGroupingEligibility(); got.Attempt != 10 || got.TopologyChecked || len(got.FailedConditions) != 0 {
		t.Fatal("earlier topology reused for a new early failure", got)
	}
}

func TestDetailedConnectionEvidenceRemainsBelowLogBound(t *testing.T) {
	m := MonitorDiagnostics{Attempts: ^uint64(0), DroppedConnectionEvents: ^uint64(0)}
	for i := 0; i < 24; i++ {
		m.ConnectionTrace = append(m.ConnectionTrace, ConnectionEvent{Attempt: ^uint64(0), Stage: "usb_mode_switch_begin", ElapsedMS: 9223372036854775807, Evidence: "PRIVATE_EVENT"})
	}
	e := compactConnectionEvidence(ApplicationResult{DeviceKind: "iPad", Status: "MONITOR_WAITING"}, m)
	d := describeGroupingEligibility(groupingEligibilityInput{RootFound: true, DriverVersion: strings.Repeat("9", 32), RootProblem: ^uint32(0), RootStateError: "PRIVATE_ERROR", EnumeratorError: "PRIVATE_ERROR"})
	d.Attempt = ^uint64(0)
	d.Status = "DIAGNOSED_UNGROUPED_NATIVE_FAILURE_REQUIRED"
	e.GroupingEligibility = &d
	e.NativeStart = compactNativeStart(StartupReadinessDiagnostic{Attempt: ^uint64(0), Status: "PRIVATE_STATUS", ExitReason: "PRIVATE_REASON", Samples: []StartupDiagnosticSample{{Controls: 2, FailedControls: 1, OrphanData: 1}}})
	body, err := json.Marshal(map[string]any{"core_version": "0.10.13", "ipad_connection": e})
	if err != nil || len(body) > 7000 || strings.Contains(string(body), "PRIVATE") {
		t.Fatalf("bytes=%d error=%v", len(body), err)
	}
	if e.NativeStart.Status != "OTHER" || e.NativeStart.FailedControls != 1 {
		t.Fatal(e.NativeStart)
	}
}

func TestGroupingEvidenceMarksPreviousAttemptInCompactSnapshot(t *testing.T) {
	previousMonitor := monitorDiagnostics
	monitorDiagnostics = newMonitorDiagnosticCounter()
	groupingEvidenceCache.Lock()
	previousGrouping := groupingEvidenceCache.latest
	groupingEvidenceCache.Unlock()
	startupReadinessHistory.Lock()
	previousStartup := startupReadinessHistory.recent
	startupReadinessHistory.recent = nil
	startupReadinessHistory.Unlock()
	t.Cleanup(func() {
		monitorDiagnostics = previousMonitor
		groupingEvidenceCache.Lock()
		groupingEvidenceCache.latest = previousGrouping
		groupingEvidenceCache.Unlock()
		startupReadinessHistory.Lock()
		startupReadinessHistory.recent = previousStartup
		startupReadinessHistory.Unlock()
	})
	RecordConnectionAttemptFor("iPad")
	recordGroupingEligibility(groupingEligibilityEvidence{Attempt: currentSoftwareAttempt()}, "DIAGNOSED_UNGROUPED_NATIVE_FAILURE_REQUIRED")
	startupReadinessHistory.record(StartupReadinessDiagnostic{Attempt: currentSoftwareAttempt(), Status: "NCM_PRESENT_NATIVE_DRIVER_START_FAILED"})
	current := CompactConnectionEvidence()
	if current.GroupingEligibility.Historical || current.NativeStart.Historical {
		t.Fatal("current evidence was marked historical")
	}
	RecordConnectionAttemptFor("iPad")
	next := CompactConnectionEvidence()
	if !next.GroupingEligibility.Historical || !next.NativeStart.Historical || next.GroupingEligibility.Attempt != 1 || next.NativeStart.Attempt != 1 || next.Attempts != 2 {
		t.Fatal("previous failure appeared current", next)
	}
	if latestGroupingEligibility().Historical {
		t.Fatal("snapshot mutated shared diagnostic cache")
	}
}
