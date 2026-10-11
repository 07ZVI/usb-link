//go:build windows && amd64

package appfirewall

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

func Connections(ctx context.Context) ([]Connection, error) {
	p := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
	if err := p.Find(); err != nil {
		return nil, err
	}
	out := []Connection{}
	paths := map[uint32]string{}
	for _, v6 := range []bool{false, true} {
		family := uintptr(windows.AF_INET)
		if v6 {
			family = windows.AF_INET6
		}
		var size uint32
		rc, _, _ := p.Call(0, uintptr(unsafe.Pointer(&size)), 0, family, 5, 0)
		if rc != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > 2<<20 {
			return nil, fmt.Errorf("TCP_TABLE_UNAVAILABLE")
		}
		var rows []Connection
		done := false
		for attempt := 0; attempt < 3; attempt++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			b := make([]byte, size)
			rc, _, _ = p.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)), 0, family, 5, 0)
			if rc == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && size <= 2<<20 {
				continue
			}
			if rc != 0 || size > uint32(len(b)) {
				return nil, fmt.Errorf("TCP_TABLE_READ_FAILED")
			}
			var err error
			rows, err = ParseTCP(b[:size], v6)
			if err != nil {
				return nil, err
			}
			done = true
			break
		}
		if !done {
			return nil, fmt.Errorf("TCP_TABLE_UNSTABLE")
		}
		for _, c := range rows {
			if _, ok := paths[c.PID]; !ok {
				h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, c.PID)
				if err == nil {
					buf := make([]uint16, 1024)
					n := uint32(len(buf))
					err = windows.QueryFullProcessImageName(h, 0, &buf[0], &n)
					windows.CloseHandle(h)
					if err == nil {
						paths[c.PID] = windows.UTF16ToString(buf[:n])
					}
				}
				if _, ok := paths[c.PID]; !ok {
					paths[c.PID] = ""
				}
			}
			c.Path = paths[c.PID]
			out = append(out, c)
			if len(out) >= 1024 {
				return out, nil
			}
		}
	}
	return out, nil
}
