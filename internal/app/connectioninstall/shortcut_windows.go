//go:build windows && amd64

package connectioninstall

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func UpdateShortcut(path string, remove bool) error {
	if Verify(path) != nil {
		return fmt.Errorf("shortcut executable ownership failed")
	}
	programs, e := UserKnownFolderPath(windows.FOLDERID_Programs, 0)
	if e != nil {
		return e
	}
	return updateShortcutAtPrograms(path, remove, programs)
}
func updateShortcutAtPrograms(path string, remove bool, programs string) error {
	if Verify(path) != nil {
		return fmt.Errorf("shortcut executable ownership failed")
	}
	if noReparse(programs) != nil {
		return fmt.Errorf("shortcut directory unavailable")
	}
	root, e := Root()
	if e != nil {
		return e
	}
	system, e := windows.GetSystemDirectory()
	if e != nil {
		return e
	}
	link := filepath.Join(programs, "USB Link.lnk")
	legacyLink := filepath.Join(programs, "隨航 USB — iPad.lnk")
	legacyRootPath, e := legacyRoot()
	if e != nil {
		return e
	}
	script := `$ErrorActionPreference='Stop';$w=New-Object -ComObject WScript.Shell;foreach($checkLink in @($env:SUHANG_LINK,$env:SUHANG_LEGACY_LINK)){if(Test-Path -LiteralPath $checkLink){if((Get-Item -LiteralPath $checkLink -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Shortcut redirected'};$l=$w.CreateShortcut($checkLink);$p=[IO.Path]::GetFullPath($l.TargetPath);$d=[IO.Path]::GetDirectoryName($p);if($l.Arguments -ne '' -or -not (([IO.Path]::GetDirectoryName($d) -ieq $env:SUHANG_ROOT -and [IO.Path]::GetFileName($p) -ceq 'USB-Link.exe') -or ([IO.Path]::GetDirectoryName($d) -ieq $env:SUHANG_LEGACY_ROOT -and [IO.Path]::GetFileName($p) -ceq 'Suhang-iPad-USB.exe'))){throw 'Shortcut belongs to another program'};foreach($q in @($d,$p,(Join-Path $d 'ownership.json'))){if((Get-Item -LiteralPath $q -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Shortcut target redirected'}};$r=Get-Content -Raw -LiteralPath (Join-Path $d 'ownership.json')|ConvertFrom-Json;if($r.product -cne $env:SUHANG_PRODUCT -or ($r.version -cnotmatch '^\d+\.\d+\.\d+$' -or ($r.version -cne [IO.Path]::GetFileName($d) -and [IO.Path]::GetFileName($d) -cne 'App')) -or (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -cne $r.sha256){throw 'Shortcut target changed'}}};if($env:SUHANG_REMOVE -eq '1'){if(Test-Path -LiteralPath $env:SUHANG_LINK){Remove-Item -LiteralPath $env:SUHANG_LINK}}else{$l=$w.CreateShortcut($env:SUHANG_LINK);$l.TargetPath=$env:SUHANG_EXE;$l.Arguments='';$l.WorkingDirectory=[IO.Path]::GetDirectoryName($env:SUHANG_EXE);$l.Description='USB Link';$l.Save()};if(Test-Path -LiteralPath $env:SUHANG_LEGACY_LINK){Remove-Item -LiteralPath $env:SUHANG_LEGACY_LINK};'OWNED_SHORTCUT_UPDATED'`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	for _, v := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(v), "SUHANG_") {
			c.Env = append(c.Env, v)
		}
	}
	flag := "0"
	if remove {
		flag = "1"
	}
	c.Env = append(c.Env, "SUHANG_LEGACY_ROOT="+legacyRootPath, "SUHANG_LEGACY_LINK="+legacyLink, "SUHANG_LINK="+link, "SUHANG_EXE="+path, "SUHANG_ROOT="+root, "SUHANG_PRODUCT="+ProductID, "SUHANG_REMOVE="+flag)
	b, e := c.Output()
	if e != nil || strings.TrimSpace(string(b)) != "OWNED_SHORTCUT_UPDATED" {
		return fmt.Errorf("shortcut update failed or ownership changed")
	}
	return nil
}
