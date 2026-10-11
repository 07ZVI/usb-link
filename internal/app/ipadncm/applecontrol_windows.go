//go:build windows && amd64

package ipadncm

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

type appleControl struct {
	ctx  context.Context
	file windows.Handle
}

func openAppleControl(ctx context.Context, node Node, path string) (*appleControl, string, error) {
	if !strings.HasSuffix(strings.ToUpper(node.IDPrefix), "&MI_01") || node.Problem != 0 || !strings.EqualFold(node.Service, "WinUSB") || strings.Join(node.UpperFilters, ",") != "WUDFRd,AppleKmdfFilter" {
		return nil, "APPLE_STACK_NOT_EXPECTED", windows.ERROR_NOT_SUPPORTED
	}
	if e := verifyInstalledAppleControlDriver(); e != nil {
		if e == windows.ERROR_NOT_SUPPORTED {
			return nil, "DRIVER_HASH_NOT_EXPECTED", e
		}
		return nil, "DRIVER_VERSION_CHECK", e
	}
	if ctx.Err() != nil {
		return nil, "TIME_LIMIT", windows.ERROR_TIMEOUT
	}
	// EvtDeviceFileCreate checks an upper-cased file name for MUX1. The plain
	// interface path used by 0.2.2 lacks it and returned ERROR_NOT_SUPPORTED.
	p, e := windows.UTF16PtrFromString(path + `\MUX1`)
	if e != nil {
		return nil, "PATH_ENCODING", e
	}
	f, e := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if e != nil {
		return nil, "APPLE_MUX1_CREATE_FILE", e
	}
	return &appleControl{ctx: ctx, file: f}, "APPLE_MUX1_OPENED", nil
}

// Only the same pinned official binaries accepted by openAppleControl are
// accepted for the absent-device preparation lease. This reads driver files.
func verifyInstalledAppleControlDriver() error {
	system, e := windows.GetSystemDirectory()
	if e != nil {
		return e
	}
	for name, expected := range map[string]string{
		"UMDF/AppleUsbFilter.dll": "84536890ac36f4fbcaeaef44ee38eb73123093e9253d07a6906f918b8b974ae8",
		"AppleKmdfFilter.sys":     "e044b74ff494725d56b292ace8d558e315ae406085ee3695d859ad97254897fa",
	} {
		b, er := os.ReadFile(filepath.Join(system, "drivers", filepath.FromSlash(name)))
		if er != nil {
			return er
		}
		if fmt.Sprintf("%x", sha256.Sum256(b)) != expected {
			return windows.ERROR_NOT_SUPPORTED
		}
	}
	return nil
}

func (a *appleControl) Close() { windows.CloseHandle(a.file) }

// No WinUSB pipe policy is applied through the Apple wrapper. Each buffered
// operation uses the existing overlapped IOCTL timeout/cancellation routine.
func (a *appleControl) Policy(byte, uint32, []byte) error { return nil }

func (a *appleControl) Control(rt, request byte, value, index uint16, out []byte) (uint32, error) {
	if a.ctx.Err() != nil {
		return 0, windows.ERROR_TIMEOUT
	}
	b, e := appleModePacket(rt, request, value, index, len(out))
	if e != nil {
		return 0, windows.ERROR_INVALID_PARAMETER
	}
	header := append([]byte(nil), b[:8]...)
	n, e := ioctl(a.ctx, a.file, 0x2200a0, b)
	if e != nil {
		return 0, e
	}
	count, e := appleModeReply(header, b, n, out)
	if e != nil {
		return 0, windows.ERROR_INVALID_DATA
	}
	return count, nil
}
