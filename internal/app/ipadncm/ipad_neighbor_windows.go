//go:build windows && amd64

package ipadncm

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The iPad answers normal traffic but not Windows' periodic unicast ARP
// probes, so Windows declared it unreachable about once a minute and stopped
// sending. A permanent neighbor entry for the verified peer MAC, scoped to the
// session's iPad interface and removed when the session ends, avoids the probe.

var (
	createIpNetEntry2 = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("CreateIpNetEntry2")
	deleteIpNetEntry2 = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("DeleteIpNetEntry2")
)

func ipadNeighborRow(index uint32, luid uint64, peer net.IP, mac [6]byte) (ipNetRow2, bool) {
	var row ipNetRow2
	v4 := peer.To4()
	if v4 == nil || index == 0 || luid == 0 || mac == [6]byte{} || mac[0]&1 != 0 {
		return row, false
	}
	a := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
	a.Family = windows.AF_INET
	copy(a.Addr[:], v4)
	row.Index, row.Luid = index, luid
	copy(row.Physical[:], mac[:])
	row.PhysicalLength = 6
	row.State = 6 // NlnsPermanent
	return row, true
}

// pinIPadNeighbor replaces any dynamic entry for the peer with a permanent one.
func pinIPadNeighbor(index uint32, luid uint64, peer net.IP, mac [6]byte) error {
	row, ok := ipadNeighborRow(index, luid, peer, mac)
	if !ok {
		return fmt.Errorf("IPAD_NEIGHBOR_PIN_INVALID")
	}
	deleteIpNetEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if rc, _, _ := createIpNetEntry2.Call(uintptr(unsafe.Pointer(&row))); rc != 0 && rc != uintptr(windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("IPAD_NEIGHBOR_PIN_%d", rc)
	}
	return nil
}

func unpinIPadNeighbor(index uint32, luid uint64, peer net.IP, mac [6]byte) {
	if row, ok := ipadNeighborRow(index, luid, peer, mac); ok {
		deleteIpNetEntry2.Call(uintptr(unsafe.Pointer(&row)))
	}
}
