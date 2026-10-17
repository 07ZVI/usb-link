package ipadncm

import "os"

// Compact process-local status, without mode inventory or device identifiers.
type LocalTrustServiceTrial struct {
	Requested     bool   `json:"requested"`
	Running       bool   `json:"running"`
	Phase         string `json:"phase"`
	Restored      bool   `json:"restored"`
	Error         string `json:"error,omitempty"`
	RestoreError  string `json:"restore_error,omitempty"`
	Before        uint32 `json:"before"`
	During        uint32 `json:"during"`
	After         uint32 `json:"after"`
	StartType     uint32 `json:"original_start_type"`
	AttemptBefore uint64 `json:"attempt_before"`
	AttemptAfter  uint64 `json:"attempt_after"`
}

func localTrustTrialSafeEarlyCancel(cleanupSafe bool, resultError string, noChangeAndReceiptAbsent bool) bool {
	return cleanupSafe && resultError == "DIAGNOSTIC_CANCELLED_BEFORE_CHANGE" && noChangeAndReceiptAbsent
}

func localTrustTrialBeforeChangeError(code string) bool {
	switch code {
	case "DIAGNOSTIC_CANCELLED_BEFORE_CHANGE", "SERVICE_MANAGER_UNAVAILABLE", "OFFICIAL_APPLE_SERVICE_NOT_FOUND", "INITIAL_SERVICE_STATE_NOT_STABLE":
		return true
	}
	return false
}

// Attempting the journal write creates a possible recovery obligation, even
// when the write fails. Only earlier exits may prove no service change.
func localTrustTrialNoChangeProof(journalAttempted bool, code string, readReceipt func() error) bool {
	return !journalAttempted && localTrustTrialBeforeChangeError(code) && os.IsNotExist(readReceipt())
}

func localTrustTrialSafeNoChange(cleanupSafe bool, code string, proven bool) bool {
	return cleanupSafe && proven && localTrustTrialBeforeChangeError(code)
}

func localTrustTrialCanResume(cleanupSafe, restored bool, restoreError string) bool {
	return cleanupSafe && restored && restoreError == ""
}

func localTrustTrialCompletion(cleanupSafe, restored bool, restoreError string) string {
	if localTrustTrialCanResume(cleanupSafe, restored, restoreError) {
		return "complete_restored"
	}
	return "recovery_required"
}
