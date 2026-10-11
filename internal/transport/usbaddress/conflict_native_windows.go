//go:build windows && amd64

package usbaddress

import (
	"fmt"
	"golang.org/x/sys/windows"
	"net/netip"
	"strings"
	"unsafe"
)

// VerifyNoForeignSubnet reads the same active IPv4 rows as ConflictScript,
// with exact LUID identity and a second proof check after the table snapshots.
// The caller must hold ConfigurationLock throughout verification and setup.
func VerifyNoForeignSubnet(index uint32, guid string, proofs []InterfaceProof) error {
	if _, e := ConflictScript(index, guid, proofs); e != nil {
		return e
	}
	if e := VerifyProofs(proofs); e != nil {
		return e
	}
	r := windows.MibIfRow2{InterfaceIndex: index}
	if windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &r) != nil || !strings.EqualFold(r.InterfaceGuid.String(), guid) {
		return fmt.Errorf("USB adapter identity changed")
	}
	var rt *windows.MibIpForwardTable2
	if e := windows.GetIpForwardTable2(windows.AF_INET, &rt); e != nil {
		return e
	}
	if rt == nil {
		return fmt.Errorf("IPv4 route table unavailable")
	}
	defer windows.FreeMibTable(unsafe.Pointer(rt))
	if rt.NumEntries > 65536 {
		return fmt.Errorf("IPv4 route table limit")
	}
	routes := make([]subnetRoute, 0, rt.NumEntries)
	for _, v := range rt.Rows() {
		addr := (*windows.RawSockaddrInet4)(unsafe.Pointer(&v.DestinationPrefix.Prefix))
		next := (*windows.RawSockaddrInet4)(unsafe.Pointer(&v.NextHop))
		if addr.Family != windows.AF_INET || next.Family != windows.AF_INET || v.DestinationPrefix.PrefixLength > 32 {
			return fmt.Errorf("invalid native route family or prefix")
		}
		routes = append(routes, subnetRoute{v.InterfaceIndex, v.InterfaceLuid, netip.PrefixFrom(netip.AddrFrom4(addr.Addr), int(v.DestinationPrefix.PrefixLength)), netip.AddrFrom4(next.Addr)})
	}
	var at *windows.MibUnicastIpAddressTable
	if e := windows.GetUnicastIpAddressTable(windows.AF_INET, &at); e != nil {
		return e
	}
	if at == nil {
		return fmt.Errorf("IPv4 address table unavailable")
	}
	defer windows.FreeMibTable(unsafe.Pointer(at))
	if at.NumEntries > 65536 {
		return fmt.Errorf("IPv4 address table limit")
	}
	addresses := make([]subnetAddress, 0, at.NumEntries)
	for _, v := range unsafe.Slice(&at.Table[0], int(at.NumEntries)) {
		addr := (*windows.RawSockaddrInet4)(unsafe.Pointer(&v.Address))
		if addr.Family != windows.AF_INET {
			return fmt.Errorf("invalid native address family")
		}
		addresses = append(addresses, subnetAddress{v.InterfaceIndex, v.InterfaceLuid, netip.AddrFrom4(addr.Addr), v.OnLinkPrefixLength})
	}
	if e := verifyUSBSubnetRows(proofs, routes, addresses); e != nil {
		return e
	}
	if e := VerifyProofs(proofs); e != nil {
		return e
	}
	check := windows.MibIfRow2{InterfaceLuid: r.InterfaceLuid}
	if windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &check) != nil || check.InterfaceIndex != index || !strings.EqualFold(check.InterfaceGuid.String(), guid) {
		return fmt.Errorf("USB adapter changed during conflict check")
	}
	return nil
}
