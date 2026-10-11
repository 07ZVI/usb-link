//go:build windows && amd64

package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"suhang/usbnet/internal/diagnostics/ipadprobe"
	"time"
	"unsafe"
)

const version = "0.1.0"

func dialog(message string, flags uintptr) uintptr {
	p, err := windows.UTF16PtrFromString(message)
	if err != nil {
		return 0
	}
	title, _ := windows.UTF16PtrFromString("隨航 — iPad USB 通道探測")
	result, _, _ := windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(title)), flags)
	return result
}
func save(r ipadprobe.Result) (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", fmt.Errorf("LOCALAPPDATA unavailable")
	}
	dir := filepath.Join(base, "Suhang", "iPadUSBProbe", version, time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	b = append(b, '\n')
	if err = os.WriteFile(filepath.Join(dir, "ipad-usb-probe.json"), b, 0600); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "iPad裝置診斷資料.zip")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	z := zip.NewWriter(f)
	entry, err := z.Create("ipad-usb-probe.json")
	if err == nil {
		_, err = entry.Write(b)
	}
	ze, fe := z.Close(), f.Close()
	if err != nil {
		return "", err
	}
	if ze != nil {
		return "", ze
	}
	if fe != nil {
		return "", fe
	}
	return path, nil
}
func summary(r ipadprobe.Result) string {
	if r.Status == "RAW_IPV6_ROUNDTRIP_CONFIRMED" {
		return "已確認 USB 隧道內的少量網路探測包能往返。\n這還不是原版 Moonlight 可用或速度達標的證明。"
	}
	if r.Status == "TUNNEL_HANDSHAKE_ONLY" {
		return "USB 隧道握手完成，但少量網路探測包尚未得到有效回應。\n請交回診斷資料，先不要更改驅動或安全設定。"
	}
	switch r.ErrorCode {
	case "APPLE_USB_SERVICE_UNAVAILABLE":
		return "未能連接 Windows 上的蘋果 USB 服務。\n請交回診斷資料，讓 Codex 判斷是否缺少官方元件。"
	case "CONNECT_EXACTLY_ONE_APPLE_USB_DEVICE":
		return "未找到唯一的 USB 蘋果裝置。\n請只保留 iPad 透過 USB 連接，再重試一次。"
	case "EXISTING_PAIR_RECORD_UNAVAILABLE", "InvalidHostID", "InvalidPairRecord", "MissingPairRecord":
		return "尚未取得可用的電腦信任配對。\n請解鎖 iPad，在蘋果官方配對畫面完成「信任此電腦」後重試。"
	case "PasswordProtected", "DeviceLocked":
		return "iPad 目前未允許配對服務。\n請解鎖 iPad 並保持畫面亮著後重試。"
	case "CONNECTED_DEVICE_IS_NOT_IPAD":
		return "目前透過 USB 連接的蘋果裝置不是 iPad。"
	case "InvalidService":
		return "iPad 沒有提供這次要測試的蘋果 USB 隧道服務。\n請交回診斷資料；先不要開啟開發者模式或安裝 VPN。"
	default:
		return "這次探測未完成，詳細停止位置已存入診斷資料。\n請交回資料，讓 Codex 判讀。"
	}
}
func main() {
	answer := dialog("請將 iPad 用 USB 線連接這台 Windows，解鎖並先完成蘋果的「信任此電腦」。\n\n是否允許這次臨時 USB 通道測試？\n\n測試會在記憶體中使用已有的配對身份，只查詢型號、系統版本及 USB 網路通道，最多約 60 秒。\n不讀取照片、文稿、備份，不匯出配對密鑰，不安裝驅動或 VPN。\n\n此程式不會替你授予電腦信任，也不會撤銷已授予的信任。", 0x4|0x20|0x100)
	if answer != 6 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := ipadprobe.Run(ctx, version)
	path, err := save(r)
	if err != nil {
		dialog("探測已停止，但無法儲存診斷資料。", 0x10)
		return
	}
	dialog(summary(r)+"\n\n測試已結束，將開啟診斷資料夾。\n請把「iPad裝置診斷資料.zip」傳回對話。\n\n"+path, 0x40)
	exec.Command(filepath.Join(os.Getenv("SystemRoot"), "explorer.exe"), "/select,"+path).Start()
}
