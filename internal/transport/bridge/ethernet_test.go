package bridge

import (
	"bytes"
	"encoding/binary"
	"suhang/usbnet/internal/transport/ncm"
	"testing"
)

var mac = [6]byte{6, 0x25, 7, 0x47, 0x6a, 0xb5}

func packet(src, dst [4]byte, fragment bool) []byte {
	b := make([]byte, 61)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8] = 64
	b[9] = 17
	if fragment {
		binary.BigEndian.PutUint16(b[6:], 0x2001)
	}
	copy(b[12:], src[:])
	copy(b[16:], dst[:])
	for i := 20; i < len(b); i++ {
		b[i] = byte(i)
	}
	binary.BigEndian.PutUint16(b[10:], ncm.Checksum(b[:20]))
	return b
}
func TestRealStackBoundaryAndFragmentRoundtrip(t *testing.T) {
	p := Peer{MTU: 1500}
	for _, fragment := range []bool{false, true} {
		b := packet(ncm.MacIP, ncm.WindowsIP, fragment)
		frame := ncm.Frame(ncm.ProbeMAC, mac, 0x800, append(b, make([]byte, 12)...))
		arp, ip := p.FromMac(frame)
		if arp != nil || !bytes.Equal(ip, b) || p.MAC != mac {
			t.Fatal("incoming not delivered unchanged")
		}
		reverse := packet(ncm.WindowsIP, ncm.MacIP, fragment)
		out, err := p.FromWindows(reverse)
		if err != nil {
			t.Fatal(err)
		}
		eth, _ := ncm.ParseEthernet(out)
		if eth.Destination != mac || eth.Source != ncm.ProbeMAC || !bytes.Equal(eth.Payload, reverse) {
			t.Fatal("outbound changed IP")
		}
	}
}
func TestDropsCorruptionOtherDestinationsAndIPv6(t *testing.T) {
	p := Peer{MAC: mac, MTU: 1500}
	good := packet(ncm.MacIP, ncm.WindowsIP, false)
	for _, mutate := range []func([]byte){func(b []byte) { b[10] ^= 1 }, func(b []byte) { b[0] = 0x44 }, func(b []byte) { b[2] = 255 }, func(b []byte) { b[0] = 0x65 }} {
		b := append([]byte(nil), good...)
		mutate(b)
		_, ip := p.FromMac(ncm.Frame(ncm.ProbeMAC, mac, 0x800, b))
		if ip != nil {
			t.Fatal("bad packet accepted")
		}
	}
	_, ip := p.FromMac(ncm.Frame(ncm.ProbeMAC, mac, 0x800, packet([4]byte{10, 77, 0, 3}, ncm.WindowsIP, false)))
	if ip != nil {
		t.Fatal("foreign source")
	}
	impostor := mac
	impostor[5]++
	_, ip = p.FromMac(ncm.Frame(ncm.ProbeMAC, impostor, 0x800, good))
	if ip != nil || p.MAC != mac {
		t.Fatal("peer changed")
	}
	if _, err := p.FromWindows(packet(ncm.WindowsIP, [4]byte{1, 1, 1, 1}, false)); err == nil {
		t.Fatal("external route accepted")
	}
	p.MTU = 40
	_, ip = p.FromMac(ncm.Frame(ncm.ProbeMAC, mac, 0x800, good))
	if ip != nil {
		t.Fatal("oversize")
	}
}
func TestARPDiscoveryBothDirections(t *testing.T) {
	p := Peer{MTU: 1500}
	req := ARPRequest()
	e, _ := ncm.ParseEthernet(req)
	if e.Source != ncm.ProbeMAC || !bytes.Equal(e.Payload[14:18], ncm.WindowsIP[:]) || !bytes.Equal(e.Payload[24:28], ncm.MacIP[:]) {
		t.Fatal("discovery wrong")
	}
	a := append([]byte(nil), e.Payload...)
	binary.BigEndian.PutUint16(a[6:], 2)
	copy(a[8:], mac[:])
	copy(a[14:], ncm.MacIP[:])
	copy(a[18:], ncm.ProbeMAC[:])
	copy(a[24:], ncm.WindowsIP[:])
	_, ip := p.FromMac(ncm.Frame(ncm.ProbeMAC, mac, 0x806, a))
	if ip != nil || p.MAC != mac {
		t.Fatal("ARP reply not learned")
	}
	binary.BigEndian.PutUint16(a[6:], 1)
	arp, ip := p.FromMac(ncm.Frame([6]byte{255, 255, 255, 255, 255, 255}, mac, 0x806, a))
	if arp == nil || ip != nil {
		t.Fatal("ARP request unanswered")
	}
	binary.BigEndian.PutUint16(a[6:], 3)
	arp, _ = p.FromMac(ncm.Frame(ncm.ProbeMAC, mac, 0x806, a))
	if arp != nil {
		t.Fatal("unknown ARP answered")
	}
}
func TestICMPIsNotEmulated(t *testing.T) {
	b := ncm.EchoRequest(mac, 0x1903)
	e, _ := ncm.ParseEthernet(b)
	ip := append([]byte(nil), e.Payload...)
	copy(ip[12:], ncm.MacIP[:])
	copy(ip[16:], ncm.WindowsIP[:])
	ip[10] = 0
	ip[11] = 0
	binary.BigEndian.PutUint16(ip[10:], ncm.Checksum(ip[:20]))
	p := Peer{MTU: 1500}
	arp, got := p.FromMac(ncm.Frame(ncm.ProbeMAC, mac, 0x800, ip))
	if arp != nil || !bytes.Equal(ip, got) || got[20] != 8 {
		t.Fatal("ping bypassed OS")
	}
}
