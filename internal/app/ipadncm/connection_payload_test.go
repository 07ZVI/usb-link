//go:build usblink_local_remote

package ipadncm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExpandedDiagnosticEnvelopesFitUSBLogRecords(t *testing.T) {
	monitor := MonitorDiagnostics{Attempts: ^uint64(0), DroppedConnectionEvents: ^uint64(0)}
	for i := 0; i < connectionEvidenceEventLimit; i++ {
		monitor.ConnectionTrace = append(monitor.ConnectionTrace, ConnectionEvent{Attempt: ^uint64(0), Stage: "grouping_restore_begin", ElapsedMS: 9223372036854775807})
	}
	connection := compactConnectionEvidence(ApplicationResult{DeviceKind: "iPad"}, monitor)
	eligibility := describeGroupingEligibility(groupingEligibilityInput{RootFound: true, RootProblem: ^uint32(0), DriverVersion: strings.Repeat("9", 32), RootStateError: "unreadable", EnumeratorError: "unreadable"})
	eligibility.Status = "DIAGNOSED_UNGROUPED_NATIVE_FAILURE_REQUIRED"
	connection.GroupingEligibility = &eligibility
	connection.GroupingReceipt = &GroupingReceiptDiagnostic{
		Attempt: ^uint64(0), ConfiguredRead: "PATH_HASH_OR_TRAILING_DATA_INVALID",
		PendingRead:  "PRODUCT_GROUPING_PENDING_CONFIGURATION_AMBIGUOUS",
		LookupResult: "PRODUCT_GROUPING_PENDING_ON_DIFFERENT_ROOT",
		ReuseResult:  "CONFIGURED_GROUPING_RECEIPT_INVALID",
		Directory:    &groupingReceiptDirectory{Status: "READ_FAILED", EntriesExamined: 128, ReceiptsExamined: 128, InvalidReceipts: 128, Truncated: true},
	}
	connection.NativeStart = compactNativeStart(StartupReadinessDiagnostic{Attempt: ^uint64(0), Status: "NCM_PRESENT_NATIVE_DRIVER_START_FAILED", ExitReason: "TEN_SECOND_CAP", FastPathReason: "CONFIGURED_RECEIPT_UNAVAILABLE_OR_INVALID", Samples: []StartupDiagnosticSample{{Controls: 2, FailedControls: 1, StartedControls: 1}}})
	for _, envelope := range []map[string]any{
		{"core_version": "0.10.14", "local_diagnostics_enabled": true, "ipad_connection": connection},
	} {
		encoded, err := json.Marshal(envelope)
		if err != nil || len(encoded) > 8192 {
			t.Fatalf("USB record too large: %d, %v", len(encoded), err)
		}
		t.Logf("diagnostic envelope: %d bytes", len(encoded))
	}
}
