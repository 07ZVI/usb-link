//go:build windows && amd64

package ipadncm

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const netDebugRowLimit = 40

func netDebugSockaddrIP(a *windows.RawSockaddrInet6) net.IP {
	switch a.Family {
	case windows.AF_INET:
		v := (*windows.RawSockaddrInet4)(unsafe.Pointer(a))
		return net.IP(append([]byte(nil), v.Addr[:]...))
	case windows.AF_INET6:
		return net.IP(append([]byte(nil), a.Addr[:]...))
	}
	return nil
}

var usbDebugSubnet = &net.IPNet{IP: net.IPv4(10, 6, 0, 0).To4(), Mask: net.CIDRMask(16, 32)}

// readNeighborTable returns the raw IPv4/IPv6 neighbor table. The caller filters.
func readNeighborTable() ([]ipNetRow2, string) {
	dll := windows.NewLazySystemDLL("iphlpapi.dll")
	get, free := dll.NewProc("GetIpNetTable2"), dll.NewProc("FreeMibTable")
	if get.Find() != nil || free.Find() != nil {
		return nil, "NEIGHBOR_API_UNAVAILABLE"
	}
	var table *ipNetTable2
	rc, _, _ := get.Call(windows.AF_UNSPEC, uintptr(unsafe.Pointer(&table)))
	if rc == uintptr(windows.ERROR_NOT_FOUND) {
		return nil, ""
	}
	if rc != 0 || table == nil {
		return nil, fmt.Sprintf("NEIGHBOR_TABLE_%d", rc)
	}
	defer free.Call(uintptr(unsafe.Pointer(table)))
	if table.Count > 4096 {
		return nil, "NEIGHBOR_TABLE_LIMIT"
	}
	return append([]ipNetRow2(nil), unsafe.Slice(&table.Rows[0], int(table.Count))...), ""
}

// peerNeighborState reports the raw IPv4 neighbor state for the session peer.
func peerNeighborState(index uint32, peer net.IP) string {
	rows, e := readNeighborTable()
	if e != "" {
		return "error:" + e
	}
	for i := range rows {
		ip := netDebugSockaddrIP(&rows[i].Address)
		if rows[i].Index == index && ip != nil && ip.Equal(peer) {
			return neighborStateName(rows[i].State)
		}
	}
	return "absent"
}

func collectNetDebug(reason string, extra uint32) NetDebugSnapshot {
	s := NetDebugSnapshot{UTC: netDebugNow(), Reason: reason}
	indices := map[uint32]bool{}
	if extra != 0 {
		indices[extra] = true
	}
	var at *windows.MibUnicastIpAddressTable
	var addresses []windows.MibUnicastIpAddressRow
	if e := windows.GetUnicastIpAddressTable(windows.AF_UNSPEC, &at); e != nil || at == nil {
		s.Error = "ADDRESS_TABLE_UNREADABLE"
	} else {
		if at.NumEntries <= 65536 {
			addresses = append(addresses, unsafe.Slice(&at.Table[0], int(at.NumEntries))...)
		}
		windows.FreeMibTable(unsafe.Pointer(at))
	}
	for i := range addresses {
		if ip := netDebugSockaddrIP(&addresses[i].Address); ip != nil && ip.To4() != nil && usbDebugSubnet.Contains(ip) {
			indices[addresses[i].InterfaceIndex] = true
		}
	}
	for i := range addresses {
		a := &addresses[i]
		ip := netDebugSockaddrIP(&a.Address)
		if !indices[a.InterfaceIndex] || ip == nil || len(s.Addresses) >= netDebugRowLimit {
			continue
		}
		s.Addresses = append(s.Addresses, NetDebugAddress{Index: a.InterfaceIndex, IP: ip.String(), Prefix: a.OnLinkPrefixLength, DadState: dadStateName(a.DadState), SkipAsSource: a.SkipAsSource != 0})
	}
	for index := range indices {
		row := windows.MibIfRow2{InterfaceIndex: index}
		d := NetDebugInterface{Index: index}
		if windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row) == nil {
			d.Alias = windows.UTF16ToString(row.Alias[:])
			d.OperStatus, d.MediaConnect = operStatusName(row.OperStatus), mediaConnectName(row.MediaConnectState)
			d.InOctets, d.OutOctets, d.InUcastPkts, d.OutUcastPkts = row.InOctets, row.OutOctets, row.InUcastPkts, row.OutUcastPkts
			d.InDiscards, d.InErrors, d.OutDiscards, d.OutErrors = row.InDiscards, row.InErrors, row.OutDiscards, row.OutErrors
		} else {
			d.OperStatus = "unreadable"
		}
		ip := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: index}
		if windows.GetIpInterfaceEntry(&ip) == nil {
			d.IPv4Readable, d.Connected = true, ip.Connected != 0
			d.Forwarding, d.WeakHostSend, d.WeakHostReceive = ip.ForwardingEnabled != 0, ip.WeakHostSend != 0, ip.WeakHostReceive != 0
			d.UseNUD, d.DadTransmits, d.NlMtu = ip.UseNeighborUnreachabilityDetection != 0, ip.DadTransmits, ip.NlMtu
			d.ReachableTimeMS, d.BaseReachableMS, d.RetransmitTimeMS, d.Metric = ip.ReachableTime, ip.BaseReachableTime, ip.RetransmitTime, ip.Metric
		}
		s.Interfaces = append(s.Interfaces, d)
	}
	rows, e := readNeighborTable()
	if e != "" && s.Error == "" {
		s.Error = e
	}
	for i := range rows {
		r := &rows[i]
		ip := netDebugSockaddrIP(&r.Address)
		if !indices[r.Index] || ip == nil || ip.IsMulticast() || ip.Equal(net.IPv4bcast) || len(s.Neighbors) >= netDebugRowLimit {
			continue
		}
		if v4 := ip.To4(); v4 != nil && v4[3] == 255 {
			continue
		}
		mac := ""
		if r.PhysicalLength == 6 {
			mac = net.HardwareAddr(r.Physical[:6]).String()
		}
		s.Neighbors = append(s.Neighbors, NetDebugNeighbor{Index: r.Index, IP: ip.String(), MAC: mac, State: neighborStateName(r.State)})
	}
	var rt *windows.MibIpForwardTable2
	if e := windows.GetIpForwardTable2(windows.AF_INET, &rt); e == nil && rt != nil {
		if rt.NumEntries <= 65536 {
			for _, v := range rt.Rows() {
				if !indices[v.InterfaceIndex] || len(s.Routes) >= netDebugRowLimit {
					continue
				}
				dst := netDebugSockaddrIP((*windows.RawSockaddrInet6)(unsafe.Pointer(&v.DestinationPrefix.Prefix)))
				next := netDebugSockaddrIP((*windows.RawSockaddrInet6)(unsafe.Pointer(&v.NextHop)))
				if dst == nil || next == nil || dst.IsMulticast() {
					continue
				}
				s.Routes = append(s.Routes, NetDebugRoute{Index: v.InterfaceIndex, Prefix: fmt.Sprintf("%s/%d", dst, v.DestinationPrefix.PrefixLength), NextHop: next.String(), Metric: v.Metric})
			}
		}
		windows.FreeMibTable(unsafe.Pointer(rt))
	} else if s.Error == "" {
		s.Error = "ROUTE_TABLE_UNREADABLE"
	}
	return s
}

func dhcpKindName(k byte) string {
	switch k {
	case 1:
		return "discover"
	case 2:
		return "offer"
	case 3:
		return "request"
	case 4:
		return "decline"
	case 5:
		return "ack"
	case 6:
		return "nak"
	case 7:
		return "release"
	case 8:
		return "inform"
	}
	return fmt.Sprintf("type%d", k)
}

func ipv4Text(b [4]byte) string { return net.IP(b[:]).String() }
