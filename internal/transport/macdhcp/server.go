// Package macdhcp handles one USB Ethernet peer's DHCP before Wintun filtering.
// It never opens a LAN DHCP socket or sends through another network adapter.
package macdhcp

import (
	"bytes"
	"encoding/binary"
	"suhang/usbnet/internal/transport/bridge"
	"suhang/usbnet/internal/transport/ipadsession"
	"suhang/usbnet/internal/transport/ncm"
	"time"
)

var broadcastMAC = [6]byte{255, 255, 255, 255, 255, 255}
var broadcastIP = [4]byte{255, 255, 255, 255}

type Server struct {
	Local, Peer               [4]byte
	Internet                  func() bool
	MAC                       [6]byte
	Window                    time.Time
	Replies                   int
	Discoveries, Offers, ACKs uint64
}

// Handle returns only a USB reply. accepted means a valid packet was consumed.
// The first eligible request fixes the Ethernet identity for this attachment;
// established is the bridge's independently learned ARP identity, if present.
func (s *Server) Handle(frame []byte, established [6]byte, now time.Time) (reply []byte, accepted bool, failure string) {
	e, err := ncm.ParseEthernet(frame)
	if err != nil || e.Type != 0x800 || (e.Destination != broadcastMAC && e.Destination != ncm.ProbeMAC) || e.Source == [6]byte{} || e.Source[0]&1 != 0 || e.Source == ncm.ProbeMAC {
		return
	}
	if established != [6]byte{} && e.Source != established || s.MAC != [6]byte{} && e.Source != s.MAC {
		return
	}
	ip, err := bridge.IPv4(e.Payload, 1500)
	if err != nil || ip[9] != 17 || binary.BigEndian.Uint16(ip[6:])&0x3fff != 0 || (!bytes.Equal(ip[16:20], broadcastIP[:]) && !bytes.Equal(ip[16:20], s.Local[:])) {
		return
	}
	h := int(ip[0]&15) * 4
	if len(ip) < h+8 {
		return
	}
	u := ip[h:]
	n := int(binary.BigEndian.Uint16(u[4:]))
	if binary.BigEndian.Uint16(u) != 68 || binary.BigEndian.Uint16(u[2:]) != 67 || n != len(u) || n < 8 || binary.BigEndian.Uint16(u[6:]) != 0 && udpChecksum(ip[12:16], ip[16:20], u) != 0 {
		return
	}
	req, err := ipadsession.ParseDHCP(u[8:], e.Source)
	if err != nil {
		return
	}
	// Direct initialization/renewal only. Do not lease an unrelated source.
	source := ip[12:16]
	if !bytes.Equal(source, []byte{0, 0, 0, 0}) && !bytes.Equal(source, s.Peer[:]) {
		return
	}
	if req.HasServer && req.Server != s.Local {
		return
	}
	if req.Kind == 4 && req.HasRequested && req.Requested == s.Peer {
		return nil, true, "MAC_DHCP_DECLINED_FIXED_ADDRESS"
	}
	internet := s.Internet != nil && s.Internet()
	b, kind := ipadsession.DHCPReplyWithDNS(req, s.Local, s.Peer, internet, internet)
	if b == nil {
		return
	}
	if s.Window.IsZero() || now.Sub(s.Window) >= time.Minute {
		s.Window = now
		s.Replies = 0
	}
	if s.Replies >= 128 {
		return nil, true, "MAC_DHCP_REPLY_LIMIT"
	}
	s.MAC = e.Source
	s.Replies++
	if req.Kind == 1 {
		s.Discoveries++
	}
	if kind == 2 {
		s.Offers++
	}
	if kind == 5 {
		s.ACKs++
	}
	// Broadcast initialization avoids depending on a not-yet-applied lease.
	// Only a CIADDR-confirmed renewal uses a unicast Ethernet/IP reply.
	dstMAC, dstIP := broadcastMAC, broadcastIP
	if req.CI == s.Peer {
		dstMAC, dstIP = s.MAC, s.Peer
	}
	return datagram(dstMAC, ncm.ProbeMAC, s.Local, dstIP, 67, 68, b), true, ""
}

func udpChecksum(src, dst, u []byte) uint16 {
	p := make([]byte, 12+len(u))
	copy(p, src)
	copy(p[4:], dst)
	p[9] = 17
	binary.BigEndian.PutUint16(p[10:], uint16(len(u)))
	copy(p[12:], u)
	return ncm.Checksum(p)
}

func datagram(dstMAC, srcMAC [6]byte, src, dst [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	b := make([]byte, 28+len(payload))
	b[0] = 0x45
	b[8] = 64
	b[9] = 17
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[12:], src[:])
	copy(b[16:], dst[:])
	binary.BigEndian.PutUint16(b[10:], ncm.Checksum(b[:20]))
	u := b[20:]
	binary.BigEndian.PutUint16(u, srcPort)
	binary.BigEndian.PutUint16(u[2:], dstPort)
	binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
	copy(u[8:], payload)
	sum := udpChecksum(src[:], dst[:], u)
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], sum)
	return ncm.Frame(dstMAC, srcMAC, 0x800, b)
}
