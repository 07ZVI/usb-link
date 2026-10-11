//go:build windows && amd64

package main

import (
	"archive/zip"
	"encoding/json"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"suhang/usbnet/internal/app/ipadncm"
	"time"
	"unsafe"
)

const version = "0.1.0"

func dialog(s string, f uintptr) uintptr {
	p, _ := windows.UTF16PtrFromString(s)
	t, _ := windows.UTF16PtrFromString("隨航 — iPad USB 網卡模式測試")
	v, _, _ := windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(t)), f)
	return v
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
			dialog("需要管理員權限讀取 USB 集線器描述。未執行測試。", 0x10)
		}
		return
	}
	if dialog("請只連接一台 iPad，解鎖並保持連線。\n\n是否允許讀取 iPad 的 USB 配置與目前驅動？\n不讀個人檔案，不匯出配對身份，不更改驅動或網路設定。\n\n如果現有 WinUSB 能讀取模式，程式會另外詢問是否嘗試切換到 USB 網卡模式；可能短暫中斷 iPad 的 USB 連線。", 0x4|0x20|0x100) != 6 {
		return
	}
	r := ipadncm.Run(version, func() bool {
		return dialog("已確認是 iPad，且現有 WinUSB 可讀取 USB 模式。\n\n是否允許發送一次網卡模式切換請求？\n這可能讓 iPad 短暫斷線並重新被電腦識別。\n不替換驅動、不修改登錄或網路；若連線異常，拔線再接即可重新檢查。", 0x4|0x20|0x100) == 6
	})
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return
	}
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		dialog("測試停止，無法找到診斷儲存位置。", 0x10)
		return
	}
	parent := filepath.Join(base, "Suhang", "iPadNCMCheck", version)
	e = os.MkdirAll(parent, 0700)
	if e != nil {
		dialog("無法儲存診斷資料。", 0x10)
		return
	}
	dir, e := os.MkdirTemp(parent, time.Now().Format("20060102-150405")+"-")
	if e != nil {
		dialog("無法儲存診斷資料。", 0x10)
		return
	}
	path := filepath.Join(dir, "iPad網卡診斷資料.zip")
	f, e := os.Create(path)
	if e != nil {
		dialog("無法儲存診斷資料。", 0x10)
		return
	}
	z := zip.NewWriter(f)
	entry, e := z.Create("ipad-ncm-check.json")
	if e == nil {
		_, e = entry.Write(append(b, '\n'))
	}
	ze, fe := z.Close(), f.Close()
	if e != nil || ze != nil || fe != nil {
		dialog("無法完成診斷壓縮檔。", 0x10)
		return
	}
	message := "測試已結束，請把「iPad網卡診斷資料.zip」傳回對話。"
	switch r.Status {
	case "NCM_DESCRIPTORS_PRESENT":
		message = "iPad 已提供 USB 網卡描述。接下來仍需驗證驅動與網路通信。\n\n" + message
	case "NCM_DESCRIPTORS_AFTER_REQUEST":
		message = "請求後在同一個 USB 連接埠讀到了網卡描述。尚未建立或驗證可用網路。\n\n" + message
	case "CONTROL_ACCESS_BLOCKED_NOT_A_SUPPORT_VERDICT":
		message = "現有驅動未提供可用的模式請求通道，因此尚未測試切換。這不代表 iPad 不支援。\n\n" + message
	case "IPAD_IDENTITY_UNCONFIRMED":
		message = "未能確認 iPad 型號，因此沒有嘗試切換。已保存 USB 描述檢查結果。\n\n" + message
	default:
		message = "測試停在：" + r.Status + "\n\n" + message
	}
	dialog(message+"\n\n"+path, 0x40)
	exec.Command(filepath.Join(os.Getenv("SystemRoot"), "explorer.exe"), "/select,"+path).Start()
}
