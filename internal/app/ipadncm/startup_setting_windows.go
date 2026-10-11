//go:build windows && amd64

package ipadncm

import (
	"fmt"
	"suhang/usbnet/internal/app/startuptelemetry"
	"suhang/usbnet/internal/app/usbhost"
	"sync"
)

var startupPreferenceMu sync.Mutex

func ReconcileStartupSettings(set func(bool) error) {
	startupPreferenceMu.Lock()
	defer startupPreferenceMu.Unlock()
	RecordStartupSettingResult(set(ConnectionStartupEnabled()))
}

// RequestStartupEnabled uses the same verified task setter and protected
// preference save as the user-facing switch. It accepts no executable, account,
// task name or command from the diagnostic caller.
func RequestStartupEnabled() error {
	// Apply even when the preference is already on: a missing or disabled task
	// must be repaired by the same strict setter, rather than saved as success.
	e := setModernStartupPreference("startup-on", true)
	RecordStartupSettingResult(e)
	return e
}

var startupSetting struct {
	sync.Mutex
	problem string
}

func RecordStartupSettingResult(e error) {
	startupSetting.Lock()
	defer startupSetting.Unlock()
	startupSetting.problem = ""
	if e != nil {
		startupSetting.problem = e.Error()
	}
}
func StartupSettingProblem() string {
	startupSetting.Lock()
	defer startupSetting.Unlock()
	return startupSetting.problem
}

var waitingHostDiagnostic struct {
	sync.Mutex
	read func() any
}

// The parent supplies its fixed, read-only recovery-directory observation.
// Neither the desktop nor a remote caller can select a path or authorize repair.
func SetSharedHostWaitingDiagnostics(read func() any) {
	waitingHostDiagnostic.Lock()
	waitingHostDiagnostic.read = read
	waitingHostDiagnostic.Unlock()
}

func sharedHostWaitingDiagnostics() any {
	waitingHostDiagnostic.Lock()
	read := waitingHostDiagnostic.read
	waitingHostDiagnostic.Unlock()
	if read != nil {
		return read()
	}
	return usbhost.SharedHostSupervisorDetails()
}

func startupTimingText(r startuptelemetry.Report) string {
	if !r.Anchors.Logon.Available {
		return "登入後就緒計時：系統登入時刻不可用；程式啟動時間另行記錄。"
	}
	text := "登入後就緒計時：由程式自動記錄"
	for _, e := range r.Events {
		if e.Stage != "device_ready" || e.SinceLogonMS == nil {
			continue
		}
		text += fmt.Sprintf(" · %s %.1f 秒", e.Device, float64(*e.SinceLogonMS)/1000)
	}
	return text + "。這是網路就緒時間，串流體驗需實際確認。"
}
