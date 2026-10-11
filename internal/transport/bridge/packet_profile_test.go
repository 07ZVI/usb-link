package bridge

import (
	"encoding/binary"
	"testing"
)

func TestPacketProfileSeparatesFragmentsACKsAndData(t *testing.T) {
	var p PacketProfile
	packet := func(size int, frag uint16, flags byte) []byte {
		ip := make([]byte, size)
		ip[0], ip[9], ip[32], ip[33] = 0x45, 6, 0x50, flags
		binary.BigEndian.PutUint16(ip[6:], frag)
		return ip
	}
	p.Observe(packet(40, 0x4000, 0x10))
	p.Observe(packet(1516, 0x4000, 0x18))
	p.Observe(packet(8000, 0x2000, 0x10))
	p.Observe(packet(16000, 0, 0x18))
	if p.Lengths != [5]uint64{1, 1, 1, 1, 0} || p.Fragments != 1 || p.TCPACKOnly != 1 || p.TCPData != 2 {
		t.Fatal(p)
	}
	if p.MaxIPLength != 16000 || p.MaxTCPPayload != 15960 || p.TCPDataBytes != 17436 {
		t.Fatal(p)
	}
}

func TestPacketProfileReadsOnlyBoundedSYNMSS(t *testing.T) {
	var p PacketProfile
	for _, mss := range []uint16{1460, 15960, 2000} {
		ip := make([]byte, 44)
		ip[0], ip[9], ip[32], ip[33] = 0x45, 6, 0x60, 0x02
		copy(ip[40:], []byte{2, 4, 0, 0})
		binary.BigEndian.PutUint16(ip[42:], mss)
		p.Observe(ip)
		ip[33] = 0x10 // An option on a non-SYN does not claim handshake MSS.
		p.Observe(ip)
		ip[33], ip[41] = 0x02, 5 // Truncated option is ignored, never indexed.
		p.Observe(ip)
	}
	if p.MSSObserved != 3 || p.MSSMin != 1460 || p.MSSMax != 15960 {
		t.Fatal(p)
	}
}
