package ipadncm

import (
	"fmt"
	"strings"
)

// This result describes only this Windows computer's saved record. It never
// claims that iPadOS forgot trust or that an existing Apple session ended.
type TrustRevokeResult struct {
	RecordRelocated           bool   `json:"record_relocated"`
	OperationMetadataRetained bool   `json:"operation_metadata_retained"`
	Code                      string `json:"code"`
	MovedToProtectedBackup    bool   `json:"moved_to_protected_backup"`
	OriginalAbsenceVerified   bool   `json:"original_absence_verified"`
	BackupMetadataVerified    bool   `json:"backup_metadata_verified"`
	OldManualBackupDeleted    bool   `json:"old_manual_backup_deleted"`
	ReconnectRequired         bool   `json:"reconnect_required"`
	Notice                    string `json:"notice"`
}

func trustRevokeLeaves(serial string) []string {
	s := strings.ToLower(serial)
	if len(s) == 25 && s[8] == '-' {
		s = s[:8] + s[9:]
	}
	if len(s) != 24 && len(s) != 40 {
		return nil
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil
		}
	}
	if len(s) == 24 {
		return []string{s + ".plist", s[:8] + "-" + s[8:] + ".plist"}
	}
	return []string{s + ".plist"}
}

const trustRevokeOldManualLeaf = "00008103-0009716E3400201E.plist"

func trustRevokeOldManualTarget(serial string) bool {
	for _, leaf := range trustRevokeLeaves(serial) {
		if strings.EqualFold(leaf, trustRevokeOldManualLeaf) {
			return true
		}
	}
	return false
}

// Each unsuccessful step stops before the next effect. Intent and any moved
// record remain available for diagnosis; no automatic rollback overwrites a
// record Apple might have recreated in the meantime.
func runTrustRevokeTransaction(intent, fresh, move, protect, durableMove, verify, complete func() error) error {
	for _, step := range []func() error{intent, fresh, move, protect, durableMove, verify, complete} {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func trustRevokeFileShape(attributes, links uint32, size uint64) error {
	// DIRECTORY=0x10, REPARSE_POINT=0x400. Hard links are deliberately rejected.
	if attributes&(0x10|0x400) != 0 || links != 1 || size == 0 || size > 512*1024 {
		return fmt.Errorf("TRUST_RECORD_NOT_SINGLE_REGULAR_BOUNDED_FILE")
	}
	return nil
}
