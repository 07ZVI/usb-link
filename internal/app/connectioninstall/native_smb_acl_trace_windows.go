//go:build windows && amd64

package connectioninstall

import (
	"errors"
	"sync"
	"syscall"
	"time"
)

type smbACLWriteResult struct {
	ID            string    `json:"id"`
	Stage         string    `json:"stage"`
	Administrator string    `json:"administrator,omitempty"`
	Succeeded     bool      `json:"succeeded"`
	WindowsError  uint32    `json:"windows_error,omitempty"`
	Observed      time.Time `json:"observed_utc"`
}

var smbACLWrites struct {
	sync.Mutex
	rows []smbACLWriteResult
}

func recordSMBACLWrite(id, stage, administrator string, err error) {
	r := smbACLWriteResult{ID: id, Stage: stage, Administrator: administrator, Succeeded: err == nil, Observed: time.Now()}
	var code syscall.Errno
	if errors.As(err, &code) {
		r.WindowsError = uint32(code)
	}
	smbACLWrites.Lock()
	defer smbACLWrites.Unlock()
	if len(smbACLWrites.rows) >= 16 {
		smbACLWrites.rows = smbACLWrites.rows[1:]
	}
	smbACLWrites.rows = append(smbACLWrites.rows, r)
}
func nativeSMBACLWriteDiagnostics() []smbACLWriteResult {
	smbACLWrites.Lock()
	defer smbACLWrites.Unlock()
	return append([]smbACLWriteResult(nil), smbACLWrites.rows...)
}

func smbACLStageLabel(stage string) string {
	switch stage {
	case "validate-journal":
		return "核對原權限記錄"
	case "open-selected-root":
		return "核對所選資料夾"
	case "validate-administrator":
		return "核對管理員身份"
	case "open-permission-handle":
		return "取得修改權限"
	case "verify-permission-handle":
		return "核對資料夾身份"
	case "apply-folder-permissions":
		return "設定 NTFS 權限"
	default:
		return "核對已保存權限"
	}
}
