//go:build windows && amd64

package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"os/exec"
	"path/filepath"
	"suhang/usbnet/internal/app/ipadncm"
	"suhang/usbnet/internal/security/applelease"
	"time"
	"unsafe"
)

const version = "0.2.3"

func dialog(text string, flags uintptr) uintptr {
	p, _ := windows.UTF16PtrFromString(text)
	title, _ := windows.UTF16PtrFromString("隨航 — iPad USB 存取測試")
	v, _, _ := windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(title)), flags)
	return v
}

type appleService struct{ s *mgr.Service }

func (s appleService) State() (uint32, error) { v, e := s.s.Query(); return uint32(v.State), e }
func (s appleService) Stop() error            { _, e := s.s.Control(svc.Stop); return e }
func (s appleService) Start() error           { return s.s.Start() }

type Result struct {
	Protocol               string            `json:"protocol"`
	Version                string            `json:"version"`
	Started                string            `json:"started_utc"`
	Error                  string            `json:"error,omitempty"`
	DriverInstallAttempted bool              `json:"driver_install_attempted"`
	ServicePause           applelease.Report `json:"apple_service_pause"`
	Probe                  *ipadncm.Result   `json:"ncm_check,omitempty"`
	AfterRestore           *ipadncm.Snapshot `json:"after_service_restore,omitempty"`
}

func inspect(r *Result) {
	m, e := mgr.Connect()
	if e != nil {
		r.Error = "SERVICE_MANAGER_UNAVAILABLE"
		return
	}
	defer m.Disconnect()
	s, e := m.OpenService("Apple Mobile Device Service")
	if e != nil {
		r.Error = "OFFICIAL_APPLE_SERVICE_NOT_FOUND"
		return
	}
	defer s.Close()
	lease := applelease.New(appleService{s})
	probe := ipadncm.RunAppleControlWithLease(version, lease.Active, func() (func(), bool) {
		allow := dialog("已透過蘋果服務確認 iPad 型號。\n\n是否允許這一次存取測試？\n\n1. 暫停 Apple Mobile Device Service，核對已安裝的官方驅動，測試它的 MUX1 控制入口。\n2. 若讀到預期的初始 USB 模式 3:3:3:0，送出一次網卡模式 3 請求。\n3. 關閉 USB 存取並恢復蘋果服務，保存結果。\n\n這不是已確認可行的方法；它用來驗證官方驅動的控制入口與裝置模式回應。可能短暫中斷其他蘋果 USB 程式，請先結束同步、備份或更新並保持這台 iPad 連線。\n\n不換驅動、不改服務啟動設定或網路設定。確認暫停後約 20 秒會觸發恢復保護；若強制結束程式，可能需要重啟 Windows 恢復服務。", 0x4|0x20|0x100) == 6
		ok := lease.Begin(allow)
		return lease.Close, ok
	})
	lease.Close()
	r.ServicePause = lease.Report()
	r.Probe = &probe
	if r.ServicePause.StopAttempted && r.ServicePause.Restored {
		snapshot := ipadncm.Inspect()
		r.AfterRestore = &snapshot
	}
	if r.ServicePause.RestoreError != "" {
		r.Error = "APPLE_SERVICE_RESTORE_NOT_CONFIRMED"
	}
}
func save(r Result) (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", fmt.Errorf("no output directory")
	}
	parent := filepath.Join(base, "Suhang", "iPadUSBAccessCheck", version)
	if e := os.MkdirAll(parent, 0700); e != nil {
		return "", e
	}
	dir, e := os.MkdirTemp(parent, time.Now().Format("20060102-150405")+"-")
	if e != nil {
		return "", e
	}
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return "", e
	}
	path := filepath.Join(dir, "iPad網卡診斷資料.zip")
	f, e := os.Create(path)
	if e != nil {
		return "", e
	}
	z := zip.NewWriter(f)
	entry, e := z.Create("ipad-usb-access-check.json")
	if e == nil {
		_, e = entry.Write(append(b, '\n'))
	}
	ze, fe := z.Close(), f.Close()
	if e != nil {
		return "", e
	}
	if ze != nil {
		return "", ze
	}
	if fe != nil {
		return "", fe
	}
	return path, nil
}
func main() {
	if !windows.GetCurrentProcessToken().IsElevated() {
		exe, e := os.Executable()
		if e != nil {
			return
		}
		verb, _ := windows.UTF16PtrFromString("runas")
		path, _ := windows.UTF16PtrFromString(exe)
		v, _, _ := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteW").Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(path)), 0, 0, 1)
		if v <= 32 {
			dialog("沒有取得管理員權限，沒有進行測試。", 0x10)
		}
		return
	}
	if dialog("這版不需要重新安裝任何元件。\n\n請只連接這台 iPad，解鎖並保持螢幕亮著；先結束蘋果裝置的同步、備份或更新。\n\n按「確定」開始讀取 USB 描述與型號。確認型號後，會另外詢問是否暫停蘋果服務及測試網卡模式。", 0x1|0x40|0x100) != 1 {
		return
	}
	r := Result{Protocol: "SUHANG-IPAD-USB-ACCESS-CHECK/1", Version: version, Started: time.Now().UTC().Format(time.RFC3339)}
	inspect(&r)
	path, e := save(r)
	if e != nil {
		dialog("測試已結束，但無法儲存診斷資料。", 0x10)
		return
	}
	text := "請將「iPad網卡診斷資料.zip」傳回對話。"
	if r.Error != "" {
		text = "結果：" + r.Error + "\n\n" + text
	}
	if r.Probe != nil {
		text = "檢查結果：" + r.Probe.Status + "\n\n" + text
	}
	if r.ServicePause.RestoreError != "" {
		text = "蘋果服務尚未確認恢復。請回傳診斷資料，並重新啟動 Windows；不要繼續備份或更新。\n\n" + text
	}
	if r.Probe != nil && (r.Probe.Status == "NCM_DESCRIPTORS_PRESENT" || r.Probe.Status == "NCM_DESCRIPTORS_AFTER_REQUEST") {
		text = "已讀到 NCM 網卡描述，可用網路與串流尚未驗證。\n\n" + text
	}
	dialog(text+"\n\n"+path, 0x40)
	if system, e := windows.GetSystemDirectory(); e == nil {
		exec.Command(filepath.Join(system, "..", "explorer.exe"), "/select,"+path).Start()
	}
}
