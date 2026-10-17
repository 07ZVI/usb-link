package ipadncm

import (
	"os"
	"strings"
	"sync"
)

// Fixed classifications only. Root IDs, receipt hashes and native errors never
// cross this boundary; none of these observations authorize configuration.
type GroupingReceiptDiagnostic struct {
	Attempt             uint64                    `json:"software_attempt"`
	Historical          bool                      `json:"from_previous_software_attempt"`
	RootAvailable       bool                      `json:"current_root_available"`
	ConfiguredRead      string                    `json:"matching_configured_receipt"`
	ConfiguredRootMatch bool                      `json:"configured_record_matches_current_root"`
	PendingRead         string                    `json:"pending_receipt"`
	PendingRootMatch    bool                      `json:"pending_record_matches_current_root"`
	LookupResult        string                    `json:"ownership_lookup_result"`
	ReuseResult         string                    `json:"configured_reuse_result"`
	Directory           *groupingReceiptDirectory `json:"failure_directory_inventory,omitempty"`
}

type groupingReceiptDirectory struct {
	Status               string `json:"status"`
	EntriesExamined      int    `json:"entries_examined"`
	ReceiptsExamined     int    `json:"receipts_examined"`
	MatchingRootReceipts int    `json:"valid_current_root_receipts"`
	OtherRootReceipts    int    `json:"valid_other_root_receipts"`
	InvalidReceipts      int    `json:"invalid_receipts"`
	UnreadableReceipts   int    `json:"unreadable_receipts"`
	Truncated            bool   `json:"truncated"`
	MatchesLatestRoot    bool   `json:"matches_latest_lookup_root"`
}

var groupingReceiptCache struct {
	sync.Mutex
	latest      *GroupingReceiptDiagnostic
	scanAttempt uint64
	scanRoot    string
	scanStarted bool
	scan        *groupingReceiptDirectory
}

func groupingReceiptReadCode(err error) string {
	if err == nil {
		return "VALID"
	}
	if os.IsNotExist(err) {
		return "ABSENT"
	}
	if os.IsPermission(err) {
		return "ACCESS_DENIED"
	}
	switch err.Error() {
	case "grouping receipt too large":
		return "TOO_LARGE"
	case "invalid grouping receipt":
		return "INVALID_RECORD"
	case "grouping receipt path or trailing data invalid":
		return "PATH_HASH_OR_TRAILING_DATA_INVALID"
	case "unsafe AMDS receipt", "unsafe network-only receipt":
		return "UNSAFE_FILE_TYPE"
	case "PRODUCT_GROUPING_STORE_UNPROVEN", "PRODUCT_GROUPING_PENDING_UNREADABLE", "PRODUCT_GROUPING_PENDING_INVALID", "PRODUCT_GROUPING_PENDING_VALUE_NOT_OWNED", "PRODUCT_GROUPING_PENDING_CONFIGURATION_AMBIGUOUS", "PRODUCT_GROUPING_PENDING_CHANGED_DURING_READ", "PRODUCT_GROUPING_PENDING_ON_DIFFERENT_ROOT", "RECOVERY_RECORD_INVALID", "RECOVERY_TARGET_KEY_UNAVAILABLE", "RECOVERY_DRIVER_ASSOCIATION_CHANGED", "RECOVERY_APPLE_BINDING_CHANGED", "RECOVERY_SOFTWARE_KEY_UNAVAILABLE", "RECOVERY_DRIVER_VERSION_CHANGED":
		return err.Error()
	default:
		return "READ_FAILED"
	}
}

func GroupingReceiptDiagnostics() *GroupingReceiptDiagnostic {
	groupingReceiptCache.Lock()
	defer groupingReceiptCache.Unlock()
	if groupingReceiptCache.latest == nil {
		return nil
	}
	d := *groupingReceiptCache.latest
	if d.Directory != nil {
		copy := *d.Directory
		d.Directory = &copy
	}
	return &d
}

func recordGroupingReceiptLookup(d GroupingReceiptDiagnostic) {
	if d.Directory != nil {
		copy := *d.Directory
		d.Directory = &copy
	}
	groupingReceiptCache.Lock()
	defer groupingReceiptCache.Unlock()
	if previous := groupingReceiptCache.latest; previous != nil && previous.Attempt == d.Attempt {
		d.ReuseResult = previous.ReuseResult
	}
	if d.ReuseResult == "" {
		d.ReuseResult = "NOT_ATTEMPTED"
	}
	groupingReceiptCache.latest = &d
}

func summarizeGroupingReceiptNames(names []string, root string, read func(string) (groupingJournal, error)) (d groupingReceiptDirectory) {
	d.Status = "READ_OK"
	if len(names) > 128 {
		names, d.Truncated = names[:128], true
	}
	for _, name := range names {
		d.EntriesExamined++
		if !strings.HasPrefix(name, "network-grouping-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		if d.ReceiptsExamined == 32 {
			d.Truncated = true
			break
		}
		d.ReceiptsExamined++
		j, err := read(name)
		if err != nil {
			switch groupingReceiptReadCode(err) {
			case "INVALID_RECORD", "TOO_LARGE", "PATH_HASH_OR_TRAILING_DATA_INVALID", "UNSAFE_FILE_TYPE":
				d.InvalidReceipts++
			default:
				d.UnreadableReceipts++
			}
		} else if strings.EqualFold(j.RootID, root) {
			d.MatchingRootReceipts++
		} else {
			d.OtherRootReceipts++
		}
	}
	return
}

func recordGroupingReuse(attempt uint64, rootAvailable bool, result string) {
	groupingReceiptCache.Lock()
	defer groupingReceiptCache.Unlock()
	if groupingReceiptCache.latest == nil || groupingReceiptCache.latest.Attempt != attempt {
		groupingReceiptCache.latest = &GroupingReceiptDiagnostic{Attempt: attempt, ConfiguredRead: "NOT_READ", PendingRead: "NOT_READ", LookupResult: "NOT_ATTEMPTED"}
	}
	groupingReceiptCache.latest.RootAvailable = rootAvailable
	groupingReceiptCache.latest.ReuseResult = result
}

// At most one bounded directory scan per software attempt. The UI reads only
// the separate cached result, never waits for filesystem enumeration.
func failureReceiptDirectory(attempt uint64, root string, scan func() groupingReceiptDirectory) *groupingReceiptDirectory {
	groupingReceiptCache.Lock()
	if groupingReceiptCache.scanStarted && groupingReceiptCache.scanAttempt == attempt {
		var out *groupingReceiptDirectory
		if groupingReceiptCache.scan != nil {
			d := *groupingReceiptCache.scan
			d.MatchesLatestRoot = groupingReceiptCache.scanRoot == root
			out = &d
		}
		groupingReceiptCache.Unlock()
		return out
	}
	groupingReceiptCache.scanAttempt, groupingReceiptCache.scanRoot, groupingReceiptCache.scanStarted = attempt, root, true
	groupingReceiptCache.scan = nil
	groupingReceiptCache.Unlock()
	d := scan()
	d.MatchesLatestRoot = true
	groupingReceiptCache.Lock()
	if groupingReceiptCache.scanAttempt == attempt && groupingReceiptCache.scanRoot == root {
		copy := d
		groupingReceiptCache.scan = &copy
	}
	groupingReceiptCache.Unlock()
	return &d
}
