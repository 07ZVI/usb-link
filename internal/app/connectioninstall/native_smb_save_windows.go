//go:build windows && amd64

package connectioninstall

import (
	"errors"
	"fmt"
	"strings"
)

// One form submission, one serialized operation. Validate both inputs first;
// retain the owned SID and existing protected rename/password journals. If the
// password fails, roll the name back, reporting any failed rollback explicitly.
func SaveNativeSMBAccount(name, password string) (nameSaved, passwordSaved bool, err error) {
	if err = ValidateSMBAccountName(name); err != nil {
		return
	}
	if password != "" {
		if err = ValidateSMBPassword(password); err != nil {
			return
		}
	}
	nativeSMBOperationMu.Lock()
	defer nativeSMBOperationMu.Unlock()
	before := NativeSMBAccountView(false)
	if !before.Exists {
		if before.Problem != "" {
			return false, false, fmt.Errorf("%s", before.Problem)
		}
		if password == "" {
			return false, false, fmt.Errorf("請設定新帳戶的密碼。")
		}
		passwordSaved, err = updateNativeSMBAccountLocked(false, password, name)
		return passwordSaved, passwordSaved, err
	}
	changed := !strings.EqualFold(name, before.LocalName)
	if changed {
		if err = RenameSMBAccount(name); err != nil {
			return
		}
		nameSaved = true
	}
	if password != "" {
		passwordSaved, err = updateNativeSMBAccountLocked(true, password, "")
		if err != nil && changed {
			rollback := RenameSMBAccount(before.LocalName)
			if rollback == nil {
				nameSaved = false
			} else {
				err = errors.Join(err, fmt.Errorf("名稱已變更，但密碼未保存；名稱恢復失敗：%w", rollback))
			}
		}
	}
	return
}
