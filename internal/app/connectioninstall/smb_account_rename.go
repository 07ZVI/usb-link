package connectioninstall

import "fmt"

type smbAccountRename struct{ From, To, SID string }

// Resolve a rename interrupted between the Windows change and receipt save.
// The verifier must check both the SID and the application's ownership marker.
// This decision only reconciles a receipt; it never authorizes another rename.
func resolveSMBAccountRename(name, sid string, j smbAccountRename, verify func(string, string) error) (string, error) {
	if sid == "" || j.SID != sid || ValidateSMBAccountName(j.From) != nil || ValidateSMBAccountName(j.To) != nil || (name != j.From && name != j.To) {
		return "", fmt.Errorf("SMB_ACCOUNT_RENAME_RECEIPT_INVALID")
	}
	if verify(j.To, sid) == nil {
		return j.To, nil
	}
	if name == j.From && verify(j.From, sid) == nil {
		return j.From, nil
	}
	return "", fmt.Errorf("SMB_ACCOUNT_RENAME_RECOVERY_REQUIRED：帳戶身份未確認，未改動其他帳戶")
}
