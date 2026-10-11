//go:build windows && amd64

package background

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func shortcut(exe string, remove bool) error {
	programs, err := windows.KnownFolderPath(windows.FOLDERID_CommonPrograms, 0)
	if err != nil {
		return err
	}
	path := filepath.Join(programs, "隨航 USB 連線管理.lnk")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ps := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	script := `$ErrorActionPreference='Stop'; $w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut($env:SUHANG_SHORTCUT); if(Test-Path -LiteralPath $env:SUHANG_SHORTCUT){if($s.Arguments -ne '--status' -or ((Split-Path -Parent (Split-Path -Parent $s.TargetPath)) -ne $env:SUHANG_ROOT -or (Split-Path -Leaf $s.TargetPath) -ne 'Suhang-USB-Setup.exe')){throw 'Existing shortcut belongs to another program'}}; `
	if remove {
		script += `if(Test-Path -LiteralPath $env:SUHANG_SHORTCUT){Remove-Item -LiteralPath $env:SUHANG_SHORTCUT -ErrorAction Stop}`
	} else {
		script += `$s.TargetPath=$env:SUHANG_EXE; $s.Arguments='--status'; $s.WorkingDirectory=[IO.Path]::GetDirectoryName($env:SUHANG_EXE); $s.Description='隨航 USB：斷開連線或重新請求同意'; $s.Save()`
	}
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	root, err := Root()
	if err != nil {
		return err
	}
	cmd.Env = append(os.Environ(), "SUHANG_ROOT="+root, "SUHANG_SHORTCUT="+path, "SUHANG_EXE="+exe)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("owned shortcut: %w (%s)", err, b)
	}
	return nil
}
