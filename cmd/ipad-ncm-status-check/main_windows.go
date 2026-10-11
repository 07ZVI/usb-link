//go:build windows && amd64

package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/app/ipadncm"
)

const version = "0.2.4"

func dialog(text string, flags uintptr) uintptr {
	p, _ := windows.UTF16PtrFromString(text)
	title, _ := windows.UTF16PtrFromString("隨航 — iPad 網卡啟動檢查")
	v, _, _ := windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(title)), flags)
	return v
}

func save(r ipadncm.StartupResult) (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", fmt.Errorf("no output directory")
	}
	parent := filepath.Join(base, "Suhang", "iPadNCMStartCheck", version)
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
	entry, e := z.Create("ipad-ncm-start-check.json")
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
			dialog("沒有取得管理員權限，沒有進行檢查。", 0x10)
		}
		return
	}
	if dialog("0.2.3 已成功讓 iPad 出現網卡介面。這版只讀取 Windows 的具體啟動錯誤與介面分組。\n\n請保持剛才那台 iPad 連線、解鎖，不要拔線；若已拔過線，先執行 0.2.3 完成模式切換，再執行這版。\n\n會在約 10 秒內讀取三份狀態。若未讀到已啟用的網卡模式，直接停止。\n\n不重裝元件、不暫停服務、不送出模式切換請求、不改驅動、登錄、IP 或安全設定。按「確定」開始。", 0x1|0x40|0x100) != 1 {
		return
	}
	r := ipadncm.RunStartupCheck(version)
	path, e := save(r)
	if e != nil {
		dialog("檢查已結束，但無法儲存診斷資料。", 0x10)
		return
	}
	message := "已保存具體啟動錯誤與介面分組。網路和串流尚未驗證。"
	if r.Status == "NCM_NOT_ACTIVE_NO_CHANGE" {
		message = "目前沒有啟用的 iPad 網卡模式，沒有變更任何設定。請先執行 0.2.3 完成模式切換，再執行這版。"
	}
	dialog(message+"\n\n結果："+r.Status+"\n請將「iPad網卡診斷資料.zip」傳回對話。\n\n"+path, 0x40)
	if system, e := windows.GetSystemDirectory(); e == nil {
		exec.Command(filepath.Join(system, "..", "explorer.exe"), "/select,"+path).Start()
	}
}
