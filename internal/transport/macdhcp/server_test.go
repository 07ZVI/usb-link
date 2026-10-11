package macdhcp

import (
	"bytes"
	"encoding/binary"
	"suhang/usbnet/internal/transport/bridge"
	"suhang/usbnet/internal/transport/ncm"
	"testing"
	"time"
)

var testMAC = [6]byte{2, 3, 4, 5, 6, 7}

func server() *Server { return &Server{Local: [4]byte{10, 6, 9, 1}, Peer: [4]byte{10, 6, 9, 2}} }
func request(kind byte, options ...byte) []byte {
	b := make([]byte, 240)
	b[0] = 1
	b[1] = 1
	b[2] = 6
	copy(b[4:8], []byte{1, 2, 3, 4})
	copy(b[28:], testMAC[:])
	copy(b[236:], []byte{99, 130, 83, 99})
	b = append(b, 53, 1, kind)
	b = append(b, options...)
	return append(b, 255)
}
func clientFrame(b []byte) []byte {
	return datagram(broadcastMAC, testMAC, [4]byte{}, broadcastIP, 68, 67, b)
}

func TestUSBDiscoverRequestRenewAndChecksums(t *testing.T) {
	s := server()
	now := time.Unix(10, 0)
	for _, kind := range []byte{1, 3} {
		f, ok, err := s.Handle(clientFrame(request(kind, 50, 4, 10, 6, 9, 2)), [6]byte{}, now)
		if !ok || err != "" {
			t.Fatal(ok, err)
		}
		e, _ := ncm.ParseEthernet(f)
		ip, err2 := bridge.IPv4(e.Payload, 1500)
		if err2 != nil || e.Destination != broadcastMAC || udpChecksum(ip[12:16], ip[16:20], ip[20:]) != 0 {
			t.Fatal("invalid reply", err2)
		}
		b := ip[28:]
		if b[0] != 2 || !bytes.Equal(b[16:20], s.Peer[:]) || !bytes.Equal(b[4:8], []byte{1, 2, 3, 4}) {
			t.Fatal("lease or transaction changed")
		}
		for i := 240; b[i] != 255; i += 2 + int(b[i+1]) {
			if b[i] == 3 || b[i] == 6 {
				t.Fatal("unrequested gateway/DNS")
			}
		}
	}
	b := request(3)
	copy(b[12:16], s.Peer[:])
	f, ok, err := s.Handle(datagram(ncm.ProbeMAC, testMAC, s.Peer, s.Local, 68, 67, b), testMAC, now)
	if !ok || err != "" || len(f) == 0 {
		t.Fatal("renew rejected", err)
	}
	e, _ := ncm.ParseEthernet(f)
	if e.Destination != testMAC || !bytes.Equal(e.Payload[16:20], s.Peer[:]) {
		t.Fatal("renew not scoped unicast")
	}
	if s.Discoveries != 1 || s.Offers != 1 || s.ACKs != 2 {
		t.Fatal(s)
	}
}

func TestUSBRejectsCorruptionFragmentsOtherIdentityAndServer(t *testing.T) {
	good := clientFrame(request(1))
	other := [6]byte{2, 9, 9, 9, 9, 9}
	for _, bad := range [][]byte{good[:30], clientFrame(request(1, 54, 4, 10, 6, 9, 99)), clientFrame(request(1, 52, 1, 1)), clientFrame(request(1, 53, 1, 1))} {
		if _, ok, _ := server().Handle(bad, [6]byte{}, time.Now()); ok {
			t.Fatal("malformed accepted")
		}
	}
	corrupt := append([]byte(nil), good...)
	corrupt[len(corrupt)-1] ^= 1
	if _, ok, _ := server().Handle(corrupt, [6]byte{}, time.Now()); ok {
		t.Fatal("UDP corruption accepted")
	}
	fragmented := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(fragmented[20:], 0x2000)
	fragmented[24] = 0
	fragmented[25] = 0
	binary.BigEndian.PutUint16(fragmented[24:], ncm.Checksum(fragmented[14:34]))
	if _, ok, _ := server().Handle(fragmented, [6]byte{}, time.Now()); ok {
		t.Fatal("fragment accepted")
	}
	if _, ok, _ := server().Handle(good, other, time.Now()); ok {
		t.Fatal("established peer changed")
	}
	s := server()
	s.MAC = other
	if _, ok, _ := s.Handle(good, [6]byte{}, time.Now()); ok {
		t.Fatal("DHCP identity changed")
	}
}

func TestUSBReplyBudgetAndDecline(t *testing.T) {
	s := server()
	now := time.Unix(10, 0)
	f := clientFrame(request(1))
	for i := 0; i < 128; i++ {
		if _, ok, e := s.Handle(f, [6]byte{}, now); !ok || e != "" {
			t.Fatal(i, e)
		}
	}
	if _, ok, e := s.Handle(f, [6]byte{}, now); !ok || e != "MAC_DHCP_REPLY_LIMIT" {
		t.Fatal("budget", ok, e)
	}
	if _, ok, e := s.Handle(f, [6]byte{}, now.Add(time.Minute)); !ok || e != "" {
		t.Fatal("renewal window", e)
	}
	if _, ok, e := s.Handle(clientFrame(request(4, 50, 4, 10, 6, 9, 2)), testMAC, now); !ok || e != "MAC_DHCP_DECLINED_FIXED_ADDRESS" {
		t.Fatal("decline", e)
	}
}

func TestDHCPFramesTraverseNCMThenLeaseARPEntersExistingBridge(t *testing.T) {
	oldLocal, oldPeer := ncm.WindowsIP, ncm.MacIP
	defer func() { ncm.WindowsIP, ncm.MacIP = oldLocal, oldPeer }()
	s := server()
	ncm.WindowsIP, ncm.MacIP = s.Local, s.Peer
	params := ncm.Parameters{Formats: 1, InMax: 16384, OutMax: 16384, InDivisor: 4, OutDivisor: 4, InAlignment: 4, OutAlignment: 4}
	b, e := ncm.Encode([][]byte{clientFrame(request(1)), clientFrame(request(3, 50, 4, 10, 6, 9, 2))}, 1, params)
	if e != nil {
		t.Fatal(e)
	}
	block, e := ncm.Decode(b)
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range block.Frames {
		if r, ok, err := s.Handle(f, [6]byte{}, time.Unix(10, 0)); !ok || err != "" || r == nil {
			t.Fatal(ok, err)
		}
	}
	if s.ACKs != 1 {
		t.Fatal("no ACK")
	}
	a := make([]byte, 28)
	binary.BigEndian.PutUint16(a, 1)
	binary.BigEndian.PutUint16(a[2:], 0x800)
	a[4] = 6
	a[5] = 4
	binary.BigEndian.PutUint16(a[6:], 1)
	copy(a[8:], testMAC[:])
	copy(a[14:], s.Peer[:])
	copy(a[24:], s.Local[:])
	p := bridge.Peer{MTU: 1500}
	r, _ := p.FromMac(ncm.Frame(broadcastMAC, testMAC, 0x806, a))
	if r == nil || p.MAC != s.MAC {
		t.Fatal("assigned peer does not enter bridge")
	}
	frame, err := p.FromWindows(ncm.EchoRequest(testMAC, 1)[14:])
	if err != nil || frame == nil {
		t.Fatal("assigned peer route rejected", err)
	}
}
