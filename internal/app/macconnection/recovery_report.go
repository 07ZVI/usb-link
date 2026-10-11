package macconnection

import (
	"bytes"
	"strings"
)

// RecoveryReport retains the reason a startup recovery gate stopped installation.
type RecoveryReport struct {
	Error   string          `json:"error,omitempty"`
	Entries []RecoveryEntry `json:"entries"`
}
type RecoveryEntry struct {
	Runtime string `json:"runtime"`
	Error   string `json:"error,omitempty"`
	Output  string `json:"network_cleanup_output,omitempty"`
}

type recoveryOutput struct{ bytes.Buffer }

func (b *recoveryOutput) Write(p []byte) (int, error) {
	n := len(p)
	if left := 16384 - b.Len(); left > 0 {
		_, _ = b.Buffer.Write(p[:min(n, left)])
	}
	return n, nil
}

func RecoveryMessage(reason string) string {
	switch {
	case strings.Contains(reason, "MAC_BRIDGE_STILL_RUNNING"):
		return "舊版 USB 橋接仍在執行。請從舊版視窗選擇「結束並產生診斷」，等待退出後再執行新版。只關閉視窗仍會在背景執行。"
	case strings.Contains(reason, "MAC_BRIDGE_LOCK_UNAVAILABLE"):
		return "無法取得 USB 橋接的執行權限，不能確認是否仍有舊版執行。具體系統錯誤已記入診斷，請回傳診斷資料。"
	case strings.Contains(reason, "MAC_RECOVERY_RECORD_INVALID"), strings.Contains(reason, "MAC_RUNTIME_OWNERSHIP_UNAVAILABLE"):
		return "舊 Mac 連線的恢復記錄未通過驗證，已保留記錄並停止啟動。這不代表舊版仍在執行。請回傳診斷資料。"
	case strings.Contains(reason, "MAC_ADAPTER_RECOVERY_UNCONFIRMED"):
		return "無法確認舊 Mac 網卡與防火牆規則已清除。系統查詢結果已記入診斷；請回傳診斷資料，不需反覆執行舊版。"
	default:
		return "舊 Mac 連線的清理未完成，沒有開始新的連線。具體失敗步驟已記入診斷，請回傳診斷資料。"
	}
}
