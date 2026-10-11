//go:build windows && amd64

package usbaddress

import (
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

// MIB_IPPATH_ROW from netioapi.h. SOCKADDR_INET is the 28-byte union
// used by x/sys for MIB_UNICASTIPADDRESS_ROW as well.
type ipPathRow struct {
	Source, Destination                           windows.RawSockaddrInet6
	InterfaceLuid                                 uint64
	InterfaceIndex                                uint32
	CurrentNextHop                                windows.RawSockaddrInet6
	PathMtu, RttMean, RttDeviation, LastReachable uint32
	IsReachable                                   uint8
	LinkTransmitSpeed, LinkReceiveSpeed           uint64
}

// Compile-time ABI checks for this amd64-only native boundary.
var _ [136 - unsafe.Sizeof(ipPathRow{})]byte
var _ [unsafe.Sizeof(ipPathRow{}) - 136]byte
var _ [96 - unsafe.Offsetof(ipPathRow{}.PathMtu)]byte
var _ [unsafe.Offsetof(ipPathRow{}.PathMtu) - 96]byte

// Query the route-selected source and exact USB peer on a verified
// interface. A missing cache entry is reported, never treated as an MTU value.
// This does not flush or change the system path cache.
func nativePeerPaths(p InterfaceProof) []map[string]any {
	out := []map[string]any{}
	for _, peer := range []byte{2, 3} {
		r := ipPathRow{InterfaceLuid: p.LUID, InterfaceIndex: p.Index}
		src := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.Source))
		dst := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.Destination))
		src.Family, dst.Family = windows.AF_UNSPEC, windows.AF_INET
		dst.Addr = [4]byte{10, 6, 9, peer}
		entry := map[string]any{"source_query": "route-selected", "destination": fmt.Sprintf("10.6.9.%d", peer)}
		rc, _, _ := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetIpPathEntry").Call(uintptr(unsafe.Pointer(&r)))
		if rc != 0 {
			entry["query_error_code"] = uint32(rc)
		} else if r.InterfaceIndex != p.Index || r.InterfaceLuid != p.LUID || src.Family != windows.AF_INET || dst.Family != windows.AF_INET || (src.Addr != [4]byte{10, 6, 9, 1} && src.Addr != [4]byte{10, 6, 9, 253} && src.Addr != [4]byte{10, 6, 9, 254}) || dst.Addr != [4]byte{10, 6, 9, peer} {
			entry["error"] = "USB_PATH_IDENTITY_CHANGED"
		} else {
			entry["source"] = fmt.Sprintf("10.6.9.%d", src.Addr[3])
			entry["path_mtu"] = r.PathMtu
			entry["reachable"] = r.IsReachable != 0
			entry["rtt_mean_ms"] = r.RttMean
		}
		out = append(out, entry)
	}
	return out
}
