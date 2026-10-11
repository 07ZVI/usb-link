//go:build windows && amd64

package ipadncm

import (
	"context"
	"encoding/binary"
	"golang.org/x/sys/windows"
	"net"
	"suhang/usbnet/internal/transport/ipadsession"
	"unsafe"
)

func sunshineNativeTCP(ipv6 bool, local, peer net.IP, scope uint32) (bool, string) {
	p := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
	if p.Find() != nil {
		return false, "TCP_TABLE_API_UNAVAILABLE"
	}
	family := uintptr(windows.AF_INET)
	if ipv6 {
		family = windows.AF_INET6
	}
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
		ok, valid := ipadsession.SunshineTCP(b[:size], ipv6, local, peer, scope)
		if !valid {
			return false, "TCP_TABLE_LAYOUT_INVALID"
		}
		return ok, ""
	}
	return false, "TCP_TABLE_CHANGED_TOO_OFTEN"
}
func applicationUSBSpeed(ctx context.Context, s Snapshot) (string, string) {
	if len(s.Devices) != 1 {
		return "尚未確認 USB 協商速率", "USB_SPEED_TARGET_AMBIGUOUS"
	}
	d := s.Devices[0]
	h, e := open(d.hub)
	if e != nil {
		return ipadsession.USBSpeedLabel(d.USBSpeedCode, false, 0), "USB_SPEED_HUB_UNAVAILABLE"
	}
	defer windows.CloseHandle(h)
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b, d.port)
	binary.LittleEndian.PutUint32(b[4:], 16)
	binary.LittleEndian.PutUint32(b[8:], 4)
	n, e := ioctl(ctx, h, 0x22045c, b)
	if e != nil || n < 16 || binary.LittleEndian.Uint32(b) != d.port || binary.LittleEndian.Uint32(b[4:]) < 16 {
		return ipadsession.USBSpeedLabel(d.USBSpeedCode, false, 0), "USB_SPEED_V2_QUERY_FAILED"
	}
	return ipadsession.USBSpeedLabel(d.USBSpeedCode, true, binary.LittleEndian.Uint32(b[12:])), ""
}
func refreshApplicationAddress(p ipadsession.Plan) string {
	if e := verifyApplicationLUID(p); e != "" {
		return e
	}
	r := addressRow(p)
	if windows.GetUnicastIpAddressEntry(&r) != nil || !ipadsession.OwnedAddress(p, ipadsession.AddressIdentity{LUID: r.InterfaceLuid, Index: r.InterfaceIndex, Prefix: uint32(r.OnLinkPrefixLength), PrefixOrigin: uint32(r.PrefixOrigin), SuffixOrigin: uint32(r.SuffixOrigin), ValidLifetime: r.ValidLifetime, PreferredLifetime: r.PreferredLifetime, CreatedAt: addressStamp(r)}) {
		return "ADDRESS_RENEWAL_OWNERSHIP_CHANGED"
	}
	r.ValidLifetime = p.AddressLifetime()
	r.PreferredLifetime = p.AddressLifetime()
	set := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SetUnicastIpAddressEntry")
	if set.Find() != nil {
		return "ADDRESS_RENEWAL_API_UNAVAILABLE"
	}
	rc, _, _ := set.Call(uintptr(unsafe.Pointer(&r)))
	if rc != 0 {
		return "ADDRESS_RENEWAL_FAILED"
	}
	return ""
}
