//go:build windows && amd64

package ipadncm

import (
	"fmt"
	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/transport/ipadsession"
	"unsafe"
)

// MIB_IPFORWARD_ROW2 / IP_ADDRESS_PREFIX, Windows amd64 ABI. Compile-time
// size and offset checks below prevent a silently misaligned IP Helper call.
type routePrefix struct {
	Address windows.RawSockaddrInet6
	Length  uint8
	_       [3]byte
}
type forwardRow struct {
	LUID                                       uint64
	Index                                      uint32
	Prefix                                     routePrefix
	NextHop                                    windows.RawSockaddrInet6
	SitePrefix                                 uint8
	_                                          [3]byte
	Valid, Preferred, Metric, Protocol         uint32
	Loopback, Autoconfigure, Publish, Immortal uint8
	Age, Origin                                uint32
}

var _ [104 - unsafe.Sizeof(forwardRow{})]byte
var _ [unsafe.Sizeof(forwardRow{}) - 104]byte
var _ [44 - unsafe.Offsetof(forwardRow{}.NextHop)]byte
var _ [unsafe.Offsetof(forwardRow{}.NextHop) - 44]byte

func peerRoute(p ipadsession.Plan) forwardRow {
	r := forwardRow{}
	windows.NewLazySystemDLL("iphlpapi.dll").NewProc("InitializeIpForwardEntry").Call(uintptr(unsafe.Pointer(&r)))
	r.LUID = p.LUID
	r.Index = p.Index
	r.Prefix.Length = 32
	r.SitePrefix = 32
	dest := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.Prefix.Address))
	dest.Family = windows.AF_INET
	copy(dest.Addr[:], parseV4(p.PeerIP()))
	next := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.NextHop))
	next.Family = windows.AF_INET
	next.Addr = [4]byte{}
	r.Valid = p.AddressLifetime()
	r.Preferred = p.AddressLifetime()
	r.Metric = p.RouteMetric()
	r.Protocol = 3
	r.Loopback = 0
	r.Autoconfigure = 0
	r.Publish = 0
	r.Immortal = 0
	r.Origin = 0
	return r
}
func routeCall(name string, r *forwardRow) uint32 {
	rc, _, _ := windows.NewLazySystemDLL("iphlpapi.dll").NewProc(name).Call(uintptr(unsafe.Pointer(r)))
	return uint32(rc)
}
func ownedPeerRoute(p ipadsession.Plan, r forwardRow) bool {
	dest := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.Prefix.Address))
	next := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.NextHop))
	return p.Version >= 4 && r.LUID == p.LUID && r.Index == p.Index && r.Prefix.Length == 32 && dest.Family == windows.AF_INET && dest.Addr == v4Array(p.PeerIP()) && next.Family == windows.AF_INET && next.Addr == [4]byte{} && r.Metric == p.RouteMetric() && r.Protocol == 3 && r.Loopback == 0 && r.Autoconfigure == 0 && r.Publish == 0 && r.Immortal == 0 && r.Valid <= p.AddressLifetime() && r.Preferred <= p.AddressLifetime()
}
func createPeerRoute(p ipadsession.Plan) string {
	if p.Version < 4 {
		return ""
	}
	for _, n := range []string{"InitializeIpForwardEntry", "GetIpForwardEntry2", "CreateIpForwardEntry2", "DeleteIpForwardEntry2", "SetIpForwardEntry2"} {
		if windows.NewLazySystemDLL("iphlpapi.dll").NewProc(n).Find() != nil {
			return "APPLICATION_ROUTE_API_UNAVAILABLE"
		}
	}
	r := peerRoute(p)
	rc := routeCall("GetIpForwardEntry2", &r)
	if rc != uint32(windows.ERROR_NOT_FOUND) && rc != uint32(windows.ERROR_FILE_NOT_FOUND) {
		return "APPLICATION_PEER_ROUTE_NOT_ABSENT"
	}
	r = peerRoute(p)
	if rc = routeCall("CreateIpForwardEntry2", &r); rc != 0 {
		return "APPLICATION_ROUTE_CREATE_" + fmt.Sprint(rc)
	}
	r = peerRoute(p)
	if routeCall("GetIpForwardEntry2", &r) != 0 || !ownedPeerRoute(p, r) {
		return "APPLICATION_ROUTE_READBACK_FAILED"
	}
	return ""
}
func removePeerRoute(p ipadsession.Plan) string {
	if p.Version < 4 {
		return ""
	}
	if e := verifyApplicationLUID(p); e == "ADAPTER_ABSENT" {
		return ""
	} else if e != "" {
		return e
	}
	r := peerRoute(p)
	rc := routeCall("GetIpForwardEntry2", &r)
	if rc == uint32(windows.ERROR_NOT_FOUND) || rc == uint32(windows.ERROR_FILE_NOT_FOUND) {
		return ""
	}
	if rc != 0 || !ownedPeerRoute(p, r) {
		return "APPLICATION_ROUTE_OWNERSHIP_CHANGED"
	}
	if routeCall("DeleteIpForwardEntry2", &r) != 0 {
		return "APPLICATION_ROUTE_DELETE_FAILED"
	}
	r = peerRoute(p)
	rc = routeCall("GetIpForwardEntry2", &r)
	if rc != uint32(windows.ERROR_NOT_FOUND) && rc != uint32(windows.ERROR_FILE_NOT_FOUND) {
		return "APPLICATION_ROUTE_ABSENCE_UNCONFIRMED"
	}
	return ""
}
func refreshPeerRoute(p ipadsession.Plan) string {
	if p.Version < 4 {
		return ""
	}
	r := peerRoute(p)
	if routeCall("GetIpForwardEntry2", &r) != 0 || !ownedPeerRoute(p, r) {
		return "APPLICATION_ROUTE_CHANGED"
	}
	r.Valid = p.AddressLifetime()
	r.Preferred = p.AddressLifetime()
	if routeCall("SetIpForwardEntry2", &r) != 0 {
		return "APPLICATION_ROUTE_REFRESH_FAILED"
	}
	return ""
}

func verifyPeerRoute(p ipadsession.Plan) string {
	if p.Version < 4 {
		return ""
	}
	r := peerRoute(p)
	if routeCall("GetIpForwardEntry2", &r) != 0 || !ownedPeerRoute(p, r) {
		return "APPLICATION_ROUTE_CHANGED"
	}
	return ""
}
