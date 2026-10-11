//go:build windows && amd64

package macconnection

import (
	"golang.org/x/sys/windows"
	"net"
	"suhang/usbnet/internal/transport/ipadsession"
	"unsafe"
)

func sunshineNativeTCP() (bool, string) {
	p := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
	if p.Find() != nil {
		return false, "TCP_TABLE_API_UNAVAILABLE"
	}
	family := uintptr(windows.AF_INET)

	var size uint32
	rc, _, _ := p.Call(0, uintptr(unsafe.Pointer(&size)), 0, family, 5, 0)
	if rc != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > 1024*1024 {
		return false, "TCP_TABLE_SIZE_UNAVAILABLE"
	}
	for i := 0; i < 3; i++ {
		b := make([]byte, size)
		rc, _, _ = p.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)), 0, family, 5, 0)
		if rc == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && size <= 1024*1024 {
			continue
		}
		if rc != 0 || size > uint32(len(b)) {
			return false, "TCP_TABLE_READ_FAILED"
		}
		ok, valid := ipadsession.SunshineTCP(b[:size], false, net.ParseIP("10.6.9.1"), net.ParseIP("10.6.9.2"), 0)
		if !valid {
			return false, "TCP_TABLE_LAYOUT_INVALID"
		}
		return ok, ""
	}
	return false, "TCP_TABLE_CHANGED_TOO_OFTEN"
}
