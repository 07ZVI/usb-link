//go:build windows && amd64

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/platform/windows/devicecheck"
)

func dialog(message string, flags uintptr) {
	text, err := windows.UTF16PtrFromString(message)
	if err != nil {
		return
	}
	title, _ := windows.UTF16PtrFromString("隨航 — USB 硬體只讀檢查")
	windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), flags)
}

func main() {
	path, err := devicecheck.Run("hardware-check-1.0.0")
	if err != nil {
		dialog("無法完成只讀檢查：\n\n"+err.Error()+"\n\n未更改驅動、網路或安全設定。", 0x10)
		return
	}
	dialog("只讀檢查已完成。\n\n將開啟資料夾，請把「裝置診斷資料.zip」傳回此對話。\n\n已收集主機板型號、USB 控制器及相關驅動清單；未更改驅動、網路或安全設定。\n這份清單不是 USB 設備模式或 iPad 串流成功的證明。\n\n"+path, 0x40)
	exec.Command(filepath.Join(os.Getenv("SystemRoot"), "explorer.exe"), "/select,"+path).Start()
}
