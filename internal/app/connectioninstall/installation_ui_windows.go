//go:build windows && amd64

package connectioninstall

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"time"
	"unsafe"
)

// Ask existing, source-verified login clients to use their normal End command.
// WM_CLOSE only hides this application's tray window. No process is killed,
// and a same-named window/process belonging to another user is never selected.
func closeInstallationLoginClients(ctx context.Context, b CoreServiceBinding) error {
	if VerifyCoreExecutable(b.Executable) != nil {
		return fmt.Errorf("INSTALL_UI_SOURCE_CHANGED")
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	var handles []windows.Handle
	var result error
	callback := windows.NewCallback(func(hwnd, lparam uintptr) uintptr {
		var class [128]uint16
		n, _, _ := user32.NewProc("GetClassNameW").Call(hwnd, uintptr(unsafe.Pointer(&class[0])), uintptr(len(class)))
		if n == 0 || windows.UTF16ToString(class[:]) != "SuhangUSBStatus061" {
			return 1
		}
		var pid uint32
		user32.NewProc("GetWindowThreadProcessId").Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid == 0 {
			return 1
		}
		h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
		if e != nil {
			return 1
		}
		keep := false
		defer func() {
			if !keep {
				windows.CloseHandle(h)
			}
		}()
		var image [32768]uint16
		length := uint32(len(image))
		if windows.QueryFullProcessImageName(h, 0, &image[0], &length) != nil || !strings.EqualFold(windows.UTF16ToString(image[:length]), b.Executable) {
			return 1
		}
		var token windows.Token
		if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) != nil {
			return 1
		}
		defer token.Close()
		u, e := token.GetTokenUser()
		session, se := shareTokenDWORD(token, windows.TokenSessionId)
		if e != nil || se != nil || u.User.Sid.String() != b.OwnerSID || session == 0 || !token.IsElevated() {
			return 1
		}
		var fresh uint32
		user32.NewProc("GetWindowThreadProcessId").Call(hwnd, uintptr(unsafe.Pointer(&fresh)))
		if fresh != pid || VerifyCoreExecutable(b.Executable) != nil {
			return 1
		}
		ok, _, err := user32.NewProc("PostMessageW").Call(hwnd, 0x111, 101, 0)
		if ok == 0 {
			result = errors.Join(result, fmt.Errorf("INSTALL_UI_CLOSE_REQUEST_FAILED: %v", err))
			return 1
		}
		keep = true
		handles = append(handles, h)
		return 1
	})
	ok, _, e := user32.NewProc("EnumWindows").Call(callback, 0)
	if ok == 0 {
		result = errors.Join(result, fmt.Errorf("INSTALL_UI_ENUMERATION_FAILED: %v", e))
	}
	defer func() {
		for _, h := range handles {
			windows.CloseHandle(h)
		}
	}()
	if result != nil {
		return result
	}
	// Older clients can need over twenty seconds to finish verified network
	// restoration. Let them finish before replacing their files; never kill them.
	wait, stop := context.WithTimeout(ctx, 60*time.Second)
	defer stop()
	for _, h := range handles {
		for wait.Err() == nil {
			status, e := windows.WaitForSingleObject(h, 100)
			if e != nil {
				return e
			}
			if status == windows.WAIT_OBJECT_0 {
				break
			}
			if status != uint32(windows.WAIT_TIMEOUT) {
				return fmt.Errorf("INSTALL_UI_WAIT_UNCONFIRMED")
			}
		}
		if wait.Err() != nil {
			return fmt.Errorf("INSTALL_UI_STILL_RUNNING: 請關閉 USB Link 介面後重新執行同一安裝程式。 %w", wait.Err())
		}
	}
	return nil
}

// Local uninstall uses the same normal client shutdown before touching private
// runtimes. Otherwise a hidden renderer can keep .NET DLLs locked indefinitely.
func CloseInstalledLoginClients(ctx context.Context, exe string) error {
	if VerifyCoreExecutable(exe) != nil {
		return fmt.Errorf("INSTALL_UI_SOURCE_UNPROVEN")
	}
	b, present, e := readCoreBinding()
	if e != nil {
		return e
	}
	if !present {
		return nil
	}
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil || u.User.Sid.String() != b.OwnerSID || !strings.EqualFold(b.Executable, exe) {
		return fmt.Errorf("INSTALL_UI_OWNER_CHANGED")
	}
	return closeInstallationLoginClients(ctx, b)
}
