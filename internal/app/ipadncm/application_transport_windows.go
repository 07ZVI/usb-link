//go:build windows && amd64

package ipadncm

import (
	"context"
	"encoding/binary"
	"golang.org/x/sys/windows"
	"net"
	"strconv"
	"suhang/usbnet/internal/transport/ipadsession"
	"syscall"
	"unsafe"
)

func parseV4(s string) []byte { return net.ParseIP(s).To4() }
func targetPeerMAC(a NetworkAdapter, peer net.IP) ([6]byte, string) {
	var mac [6]byte
	dll := windows.NewLazySystemDLL("iphlpapi.dll")
	get, free := dll.NewProc("GetIpNetTable2"), dll.NewProc("FreeMibTable")
	if get.Find() != nil || free.Find() != nil {
		return mac, "APPLICATION_NEIGHBOR_API_UNAVAILABLE"
	}
	var table *ipNetTable2
	rc, _, _ := get.Call(windows.AF_UNSPEC, uintptr(unsafe.Pointer(&table)))
	if rc != 0 || table == nil {
		return mac, "APPLICATION_PEER_MAC_UNAVAILABLE"
	}
	defer free.Call(uintptr(unsafe.Pointer(table)))
	if table.Count > 4096 {
		return mac, "APPLICATION_NEIGHBOR_LIMIT"
	}
	found := false
	for _, row := range unsafe.Slice(&table.Rows[0], int(table.Count)) {
		if row.Luid != a.luid || row.Index != a.InterfaceIndex || row.PhysicalLength != 6 || row.State == 0 || row.State == 1 || row.Flags&2 != 0 {
			continue
		}
		var ip net.IP
		if row.Address.Family == windows.AF_INET6 {
			ip = net.IP(row.Address.Addr[:])
		} else if row.Address.Family == windows.AF_INET {
			v := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
			ip = net.IP(v.Addr[:])
		}
		if !ip.Equal(peer) {
			continue
		}
		if found {
			return mac, "APPLICATION_PEER_MAC_AMBIGUOUS"
		}
		found = true
		copy(mac[:], row.Physical[:6])
	}
	if !found || mac == [6]byte{} || mac[0]&1 != 0 {
		return mac, "APPLICATION_PEER_MAC_UNAVAILABLE"
	}
	return mac, ""
}

func dhcpSocket(index uint32) (*net.UDPConn, string) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var e error
		err := c.Control(func(fd uintptr) {
			for _, opt := range []struct{ level, name, value int }{{windows.SOL_SOCKET, -5, 1}, {windows.SOL_SOCKET, windows.SO_BROADCAST, 1}, {windows.IPPROTO_IP, windows.IP_PKTINFO, 1}, {windows.IPPROTO_IP, 31, int(binary.BigEndian.Uint32([]byte{byte(index), byte(index >> 8), byte(index >> 16), byte(index >> 24)}))}} {
				if er := windows.SetsockoptInt(windows.Handle(fd), opt.level, opt.name, opt.value); er != nil {
					e = er
					break
				}
			}
		})
		if err != nil {
			return err
		}
		return e
	}}
	pc, e := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:67")
	if e != nil {
		return nil, "DHCP_PORT_OR_SCOPE_UNAVAILABLE"
	}
	return pc.(*net.UDPConn), ""
}
func sendDHCP(c *net.UDPConn, b []byte, p ipadsession.Plan, renew bool) error {
	dest := net.IPv4bcast
	if renew {
		dest = net.ParseIP(p.PeerIP())
	}
	_, _, e := c.WriteMsgUDP(b, ipadsession.PacketControl(net.ParseIP(p.LocalAddress()), p.Index), &net.UDPAddr{IP: dest, Port: 68})
	return e
}
func peerAddrString(p ipadsession.Plan) string {
	return net.JoinHostPort(p.ServerIP, strconv.Itoa(10690))
}
