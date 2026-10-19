// Package bridge implements the point-to-point IPv4 Ethernet/Wintun boundary.
package bridge

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"suhang/usbnet/internal/transport/ncm"
)

type Peer struct {
	MAC        [6]byte
	MTU        int
	Internet   func(netip.Addr) bool
	OnInternet func(inbound bool)
}

func validMAC(m [6]byte) bool { return m != [6]byte{} && m[0]&1 == 0 && m != ncm.ProbeMAC }
func (p *Peer) learn(m [6]byte) bool {
	if !validMAC(m) || (p.MAC != [6]byte{} && p.MAC != m) {
		return false
	}
	p.MAC = m
	return true
}

// IPv4 trims Ethernet padding, preserves fragments and rejects corrupt headers.
func IPv4(b []byte, mtu int) ([]byte, error) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return nil, fmt.Errorf("not IPv4")
	}
	h := int(b[0]&15) * 4
	n := int(binary.BigEndian.Uint16(b[2:]))
	if h < 20 || h > len(b) || n < h || n > len(b) || n > mtu || ncm.Checksum(b[:h]) != 0 {
		return nil, fmt.Errorf("invalid IPv4 length/header")
	}
	return b[:n], nil
}

// FromMac returns ARP responses for USB and IPv4 packets for the real OS stack.
// It deliberately never synthesizes ICMP replies: ping must traverse Wintun.
func (p *Peer) FromMac(frame []byte) (arp, ip []byte) {
	arp, ip, _ = p.FromMacReason(frame)
	return arp, ip
}

// FromMacReason is FromMac plus the first reason a frame was not accepted. The
// decision is identical; the reason is for low-overhead diagnostics only.
func (p *Peer) FromMacReason(frame []byte) (arp, ip []byte, reason DropReason) {
	e, err := ncm.ParseEthernet(frame)
	if err != nil {
		return nil, nil, DropEthernet
	}
	if e.Type == 0x806 {
		a := e.Payload
		if len(a) < 28 || binary.BigEndian.Uint16(a) != 1 || binary.BigEndian.Uint16(a[2:]) != 0x800 || a[4] != 6 || a[5] != 4 {
			return nil, nil, DropARPMalformed
		}
		var sender [6]byte
		copy(sender[:], a[8:14])
		if sender != e.Source || !bytes.Equal(a[14:18], ncm.MacIP[:]) || !bytes.Equal(a[24:28], ncm.WindowsIP[:]) {
			return nil, nil, DropARPAddress
		}
		op := binary.BigEndian.Uint16(a[6:])
		if op != 1 && op != 2 {
			return nil, nil, DropARPMalformed
		}
		if op == 2 && (e.Destination != ncm.ProbeMAC || !bytes.Equal(a[18:24], ncm.ProbeMAC[:])) {
			return nil, nil, DropARPAddress
		}
		if !p.learn(sender) {
			return nil, nil, DropPeerMAC
		}
		if op == 1 {
			reply, _, _ := ncm.ARPReply(frame)
			return reply, nil, DropNone
		}
		return nil, nil, DropNone
	}
	if e.Type != 0x800 {
		return nil, nil, DropEtherType
	}
	if e.Destination != ncm.ProbeMAC {
		return nil, nil, DropDestinationMAC
	}
	b, err := IPv4(e.Payload, p.MTU)
	if err != nil {
		if len(e.Payload) >= 20 && e.Payload[0]>>4 == 4 && int(binary.BigEndian.Uint16(e.Payload[2:])) > p.MTU {
			return nil, nil, DropOversize
		}
		return nil, nil, DropIPv4Invalid
	}
	if !bytes.Equal(b[12:16], ncm.MacIP[:]) || (!bytes.Equal(b[16:20], ncm.WindowsIP[:]) && (p.Internet == nil || !p.Internet(netip.AddrFrom4([4]byte(b[16:20]))))) {
		return nil, nil, DropIPAddress
	}
	if !p.learn(e.Source) {
		return nil, nil, DropPeerMAC
	}
	if !bytes.Equal(b[16:20], ncm.WindowsIP[:]) && p.OnInternet != nil {
		p.OnInternet(false)
	}
	return nil, b, DropNone
}

func (p *Peer) FromWindows(packet []byte) ([]byte, error) {
	return p.FromWindowsInto(packet, nil)
}

// FromWindowsInto keeps the same validation as FromWindows, using caller-owned
// non-aliasing frame storage whose lifetime ends at the next reuse.
func (p *Peer) FromWindowsInto(packet, storage []byte) ([]byte, error) {
	b, err := IPv4(packet, p.MTU)
	if err != nil {
		return nil, err
	}
	if (!bytes.Equal(b[12:16], ncm.WindowsIP[:]) && (p.Internet == nil || !p.Internet(netip.AddrFrom4([4]byte(b[12:16]))))) || !bytes.Equal(b[16:20], ncm.MacIP[:]) {
		return nil, fmt.Errorf("outside USB peer addresses")
	}
	if p.MAC == [6]byte{} {
		return nil, fmt.Errorf("peer not resolved")
	}
	if !bytes.Equal(b[12:16], ncm.WindowsIP[:]) && p.OnInternet != nil {
		p.OnInternet(true)
	}
	return ncm.FrameInto(storage, p.MAC, ncm.ProbeMAC, 0x800, b), nil
}

func ARPRequest() []byte {
	a := make([]byte, 28)
	binary.BigEndian.PutUint16(a, 1)
	binary.BigEndian.PutUint16(a[2:], 0x800)
	a[4] = 6
	a[5] = 4
	binary.BigEndian.PutUint16(a[6:], 1)
	copy(a[8:], ncm.ProbeMAC[:])
	copy(a[14:], ncm.WindowsIP[:])
	copy(a[24:], ncm.MacIP[:])
	return ncm.Frame([6]byte{255, 255, 255, 255, 255, 255}, ncm.ProbeMAC, 0x806, a)
}
