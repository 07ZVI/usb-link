package ncm

import (
	"bytes"
	"net"
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func TestUnifiedProfileARPAndICMPRoundTrip(t *testing.T) {
	oldWindows, oldMac := WindowsIP, MacIP
	defer func() { WindowsIP, MacIP = oldWindows, oldMac }()
	p, err := usbaddress.Lookup(usbaddress.Unified)
	if err != nil {
		t.Fatal(err)
	}
	copy(WindowsIP[:], net.ParseIP(p.Windows).To4())
	copy(MacIP[:], net.ParseIP(p.Peer).To4())
	peer := [6]byte{2, 3, 4, 5, 6, 7}
	a := make([]byte, 28)
	be.PutUint16(a, 1)
	be.PutUint16(a[2:], 0x800)
	a[4], a[5] = 6, 4
	be.PutUint16(a[6:], 1)
	copy(a[8:], peer[:])
	copy(a[14:], MacIP[:])
	copy(a[24:], WindowsIP[:])
	reply, got, err := ARPReply(Frame([6]byte{255, 255, 255, 255, 255, 255}, peer, 0x806, a))
	if err != nil || got != peer || len(reply) < 42 || !bytes.Equal(reply[28:32], []byte{10, 6, 9, 1}) || !bytes.Equal(reply[38:42], []byte{10, 6, 9, 2}) {
		t.Fatal("unified ARP reply", err)
	}
	f := EchoRequest(peer, 9)
	_, ip, err := IPv4ICMP(f)
	if err != nil || ip == nil || !bytes.Equal(ip[12:16], []byte{10, 6, 9, 1}) || !bytes.Equal(ip[16:20], []byte{10, 6, 9, 2}) {
		t.Fatal("unified probe/checksum", err)
	}
	// Simulate the peer reply using the same checksum-verified implementation.
	WindowsIP, MacIP = MacIP, WindowsIP
	response := EchoReply(f)
	WindowsIP, MacIP = MacIP, WindowsIP
	if !IsProbeEchoReply(response, 9) {
		t.Fatal("unified ICMP round trip")
	}
	copy(a[14:], []byte{10, 77, 0, 1})
	if r, _, _ := ARPReply(Frame([6]byte{255, 255, 255, 255, 255, 255}, peer, 0x806, a)); r != nil {
		t.Fatal("legacy peer accepted under unified profile")
	}
}
