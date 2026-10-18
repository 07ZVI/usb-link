package ipadncm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestGroupingReceiptReadClassificationDoesNotExportNativeErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, "VALID"}, {os.ErrNotExist, "ABSENT"}, {os.ErrPermission, "ACCESS_DENIED"},
		{errors.New("invalid grouping receipt"), "INVALID_RECORD"},
		{errors.New("grouping receipt path or trailing data invalid"), "PATH_HASH_OR_TRAILING_DATA_INVALID"},
		{errors.New("PRODUCT_GROUPING_PENDING_ON_DIFFERENT_ROOT"), "PRODUCT_GROUPING_PENDING_ON_DIFFERENT_ROOT"},
		{&os.PathError{Op: "open", Path: "PRIVATE_DEVICE", Err: os.ErrNotExist}, "ABSENT"},
		{errors.New("PRIVATE_DEVICE and PRIVATE_PATH"), "READ_FAILED"},
	} {
		if got := groupingReceiptReadCode(tc.err); got != tc.want {
			t.Fatalf("got=%s want=%s", got, tc.want)
		}
	}
}

func TestGroupingReceiptInventoryBoundsAndCounts(t *testing.T) {
	names := []string{"unrelated", "network-grouping-current.json", "network-grouping-other.json", "network-grouping-invalid.json", "network-grouping-unreadable.json"}
	got := summarizeGroupingReceiptNames(names, "PRIVATE_ROOT", func(name string) (groupingJournal, error) {
		switch name {
		case names[1]:
			return groupingJournal{RootID: "private_root"}, nil
		case names[2]:
			return groupingJournal{RootID: "PRIVATE_OTHER_ROOT"}, nil
		case names[3]:
			return groupingJournal{}, errors.New("invalid grouping receipt")
		default:
			return groupingJournal{}, errors.New("PRIVATE_READ_ERROR")
		}
	})
	if got.EntriesExamined != 5 || got.ReceiptsExamined != 4 || got.MatchingRootReceipts != 1 || got.OtherRootReceipts != 1 || got.InvalidReceipts != 1 || got.UnreadableReceipts != 1 {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "PRIVATE") || strings.Contains(string(b), ".json") {
		t.Fatal("identity leaked")
	}
	for _, receiptNames := range []bool{false, true} {
		many := make([]string, 129)
		for i := range many {
			if receiptNames {
				many[i] = "network-grouping-private.json"
			} else {
				many[i] = "other"
			}
		}
		reads := 0
		got = summarizeGroupingReceiptNames(many, "PRIVATE", func(string) (groupingJournal, error) { reads++; return groupingJournal{}, nil })
		if !got.Truncated || got.EntriesExamined > 128 || reads > 32 {
			t.Fatal(got, reads)
		}
		if receiptNames && reads != 32 {
			t.Fatal(reads)
		}
	}
}

func TestGroupingReceiptScanCachedPerAttemptAndSnapshotCopied(t *testing.T) {
	groupingReceiptCache.Lock()
	previous, previousScan := groupingReceiptCache.latest, groupingReceiptCache.scan
	previousAttempt, previousRoot, previousStarted := groupingReceiptCache.scanAttempt, groupingReceiptCache.scanRoot, groupingReceiptCache.scanStarted
	groupingReceiptCache.latest, groupingReceiptCache.scan, groupingReceiptCache.scanStarted = nil, nil, false
	groupingReceiptCache.Unlock()
	t.Cleanup(func() {
		groupingReceiptCache.Lock()
		groupingReceiptCache.latest, groupingReceiptCache.scan = previous, previousScan
		groupingReceiptCache.scanAttempt, groupingReceiptCache.scanRoot, groupingReceiptCache.scanStarted = previousAttempt, previousRoot, previousStarted
		groupingReceiptCache.Unlock()
	})
	reads := 0
	scan := func() groupingReceiptDirectory { reads++; return groupingReceiptDirectory{Status: "READ_OK"} }
	first := failureReceiptDirectory(1, "PRIVATE_ROOT", scan)
	recordGroupingReceiptLookup(GroupingReceiptDiagnostic{Attempt: 1, ConfiguredRead: "ABSENT", Directory: first})
	first.Status = "PRIVATE_MUTATION"
	recordGroupingReuse(1, true, "NO_MATCHING_RECEIPT_OR_PENDING")
	for i := 0; i < 20; i++ {
		_ = failureReceiptDirectory(1, "PRIVATE_ROOT", scan)
	}
	changedRoot := failureReceiptDirectory(1, "OTHER_ROOT", scan)
	if reads != 1 || changedRoot.MatchesLatestRoot || changedRoot.Status != "READ_OK" {
		t.Fatal(reads, changedRoot)
	}
	got := GroupingReceiptDiagnostics()
	if got.ReuseResult != "NO_MATCHING_RECEIPT_OR_PENDING" || got.Directory.Status != "READ_OK" {
		t.Fatal(got)
	}
	got.Directory.Status = "PRIVATE_MUTATION"
	if GroupingReceiptDiagnostics().Directory.Status != "READ_OK" {
		t.Fatal("snapshot shares cache")
	}
	recordGroupingReceiptLookup(GroupingReceiptDiagnostic{Attempt: 1, ConfiguredRead: "ABSENT"})
	if GroupingReceiptDiagnostics().ReuseResult != "NO_MATCHING_RECEIPT_OR_PENDING" {
		t.Fatal("same-attempt lookup erased reuse result")
	}
	_ = failureReceiptDirectory(2, "PRIVATE_ROOT", scan)
	recordGroupingReceiptLookup(GroupingReceiptDiagnostic{Attempt: 2, ConfiguredRead: "VALID"})
	if reads != 2 || GroupingReceiptDiagnostics().ReuseResult != "NOT_ATTEMPTED" {
		t.Fatal("new attempt reused old outcome")
	}
}

func TestGroupingReceiptCompactEnvelopeBound(t *testing.T) {
	m := MonitorDiagnostics{Attempts: ^uint64(0), AutomaticRetries: ^uint64(0), ManualRetries: ^uint64(0), DroppedConnectionEvents: ^uint64(0)}
	for i := 0; i < 12; i++ {
		m.ConnectionTrace = append(m.ConnectionTrace, ConnectionEvent{Attempt: ^uint64(0), Stage: "grouping_restore_begin", ElapsedMS: 9223372036854775807})
	}
	e := compactConnectionEvidence(ApplicationResult{DeviceKind: "iPad", Status: "MONITOR_WAITING"}, m)
	d := describeGroupingEligibility(groupingEligibilityInput{RootFound: true, DriverVersion: strings.Repeat("9", 32), RootProblem: ^uint32(0), RootStateError: "PRIVATE_ERROR", EnumeratorError: "PRIVATE_ERROR"})
	d.Attempt, d.Status = ^uint64(0), "DIAGNOSED_UNGROUPED_NATIVE_FAILURE_REQUIRED"
	e.GroupingEligibility = &d
	e.GroupingReceipt = &GroupingReceiptDiagnostic{Attempt: ^uint64(0), ConfiguredRead: "PATH_HASH_OR_TRAILING_DATA_INVALID", PendingRead: "PRODUCT_GROUPING_PENDING_CONFIGURATION_AMBIGUOUS", LookupResult: "PRODUCT_GROUPING_PENDING_CHANGED_DURING_READ", ReuseResult: "REUSED_OBSERVATION_OR_COMMIT_FAILED", Directory: &groupingReceiptDirectory{Status: "DIRECTORY_ACCESS_DENIED", EntriesExamined: 128, ReceiptsExamined: 32, OtherRootReceipts: 32, InvalidReceipts: 32, UnreadableReceipts: 32}}
	e.NativeStart = compactNativeStart(StartupReadinessDiagnostic{Attempt: ^uint64(0), Status: "NCM_NATIVE_NODE_NO_PROBLEM_OBSERVED_NOT_NETWORK_PROOF", ExitReason: "OWNED_PRODUCT_PENDING_OPERATIONAL_TOPOLOGY_PROVEN", FastPathReason: "CONFIGURED_CM_NODE_ROOT_RELATIONSHIP_UNPROVEN"})
	body, err := json.Marshal(map[string]any{"core_version": "0.10.14", "ipad_connection": e})
	if err != nil || len(body) > 8000 {
		t.Fatalf("bytes=%d err=%v", len(body), err)
	}
	t.Logf("bounded envelope bytes=%d", len(body))
}

func TestCompactNativeStartIncludesConfiguredProofWithoutNativeText(t *testing.T) {
	d := StartupReadinessDiagnostic{FastPathReason: "CONFIGURED_RECEIPT_UNAVAILABLE_OR_INVALID", Samples: []StartupDiagnosticSample{{FastPathReason: "CONFIGURED_REGISTRY_NOT_OWNED", ConfiguredProof: configuredStartupEvidence{ReceiptValid: true, SameUSBRoot: true}, Nodes: []StartupDiagnosticNode{{NodePrefix: "PRIVATE_NODE"}}}}}
	got := compactNativeStart(d)
	if got.FastPathReason != "CONFIGURED_REGISTRY_NOT_OWNED" || !got.ConfiguredProof.ReceiptValid || got.ConfiguredProof.RegistryOwned {
		t.Fatal(got)
	}
	d.Samples[0].FastPathReason = "PRIVATE_ERROR"
	b, _ := json.Marshal(compactNativeStart(d))
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("native diagnostic leaked")
	}
}

func TestReceiptsAreExaminedEvenWhenUnrelatedFilesFillTheCap(t *testing.T) {
	names := make([]string, 0, 201)
	for i := 0; i < 200; i++ {
		names = append(names, fmt.Sprintf("a-unrelated-%03d", i))
	}
	names = append(names, "network-grouping-z.json")
	reads := 0
	got := summarizeGroupingReceiptNames(names, "ROOT", func(string) (groupingJournal, error) { reads++; return groupingJournal{RootID: "ROOT"}, nil })
	if reads != 1 || got.MatchingRootReceipts != 1 || !got.Truncated {
		t.Fatal(got, reads)
	}
}
