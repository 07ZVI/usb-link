//go:build windows && amd64 && usblink_local_remote

package devicecheck

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Run needs no administrator rights and writes only its own diagnostic files.
func Run(version string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ps := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	b, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", Script).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read-only device check failed: %w", err)
	}
	if len(b) > 512*1024 || !json.Valid(b) {
		return "", fmt.Errorf("invalid or oversized device inventory")
	}
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "Suhang", "USBNet", version, "device-check")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "usb-device-check.json"), b, 0600); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "裝置診斷資料.zip")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	z := zip.NewWriter(f)
	entry, err := z.Create("usb-device-check.json")
	if err == nil {
		_, err = entry.Write(b)
	}
	closeZIP, closeFile := z.Close(), f.Close()
	if err != nil {
		return "", err
	}
	if closeZIP != nil {
		return "", closeZIP
	}
	if closeFile != nil {
		return "", closeFile
	}
	return path, nil
}
