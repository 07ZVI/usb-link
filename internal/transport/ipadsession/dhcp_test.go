package ipadsession

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

var testMAC = [6]byte{2, 3, 4, 5, 6, 7}

func client(kind byte, options ...byte) []byte {
	b := make([]byte, 240)
	b[0] = 1
	b[1] = 1
	b[2] = 6
	copy(b[4:8], []byte{1, 2, 3, 4})
	copy(b[28:], testMAC[:])
	copy(b[236:], []byte{99, 130, 83, 99})
	return append(append(b, 53, 1, kind), append(options, 255)...)
}
func TestDHCPDirectPeerDORAAndRenewNoInternetRoutes(t *testing.T) {
	server, peer := [4]byte{10, 77, 123, 1}, [4]byte{10, 77, 123, 2}
	for _, kind := range []byte{1, 3} {
		b := client(kind, 50, 4, 10, 77, 123, 2, 61, 7, 1, 2, 3, 4, 5, 6, 7)
		r, e := ParseDHCP(b, testMAC)
		if e != nil {
			t.Fatal(e)
		}
		out, replyKind := DHCPReply(r, server, peer)
		if len(out) != 300 || out[0] != 2 || replyKind != kind+1+(kind/3) || !bytes.Equal(out[4:8], b[4:8]) || !bytes.Equal(out[16:20], peer[:]) {
			t.Fatal("bad offer/ACK", replyKind)
		}
		for i := 240; out[i] != 255; {
			code, n := out[i], int(out[i+1])
			if code == 3 || code == 6 {
				t.Fatal("default route or DNS advertised")
			}
			i += 2 + n
		}
	}
	b := client(3)
	copy(b[12:16], peer[:])
	r, e := ParseDHCP(b, testMAC)
	if e != nil {
		t.Fatal(e)
	}
	if out, k := DHCPReply(r, server, peer); len(out) == 0 || k != 5 {
		t.Fatal("renew rejected")
	}
	r.HasServer = true
	r.Server = [4]byte{10, 77, 123, 99}
	if out, _ := DHCPReply(r, server, peer); out != nil {
		t.Fatal("other server hijacked")
	}
	r.HasServer = false
	r.HasRequested = true
	r.Requested = [4]byte{10, 77, 123, 3}
	if out, _ := DHCPReply(r, server, peer); out != nil {
		t.Fatal("wrong peer assigned")
	}
}
func TestDHCPRejectsOtherPeerRelayOverloadAndMalformedOptions(t *testing.T) {
	good := client(1)
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:239] }, func(b []byte) []byte { b[28] ^= 1; return b }, func(b []byte) []byte { b[24] = 1; return b },
		func(b []byte) []byte { b[0] = 2; return b }, func(b []byte) []byte { b[3] = 1; return b },
		func(b []byte) []byte { return append(b[:len(b)-1], 52, 1, 1, 255) }, func(b []byte) []byte { return append(b[:len(b)-1], 53, 1, 3, 255) },
		func(b []byte) []byte { return append(b[:len(b)-1], 50, 4, 1, 2, 255) }, func(b []byte) []byte { return b[:len(b)-1] },
	} {
		if _, e := ParseDHCP(mutate(append([]byte(nil), good...)), testMAC); e == nil {
			t.Fatal("unsafe DHCP accepted")
		}
	}
}
func TestWindowsAncillaryIdentityIsRequiredBeforeDHCP(t *testing.T) {
	b := PacketControl(net.IPv4(10, 77, 123, 1), 25)
	if index, ok := PacketInterface(b); !ok || index != 25 {
		t.Fatal(index, ok)
	}
	for _, bad := range [][]byte{nil, b[:23], append(append([]byte(nil), b...), b...), make([]byte, 24)} {
		if _, ok := PacketInterface(bad); ok {
			t.Fatal("ambiguous pktinfo accepted")
		}
	}
	binary.LittleEndian.PutUint32(b[20:24], 0)
	if _, ok := PacketInterface(b); ok {
		t.Fatal("zero interface accepted")
	}
}
func FuzzDHCPAndPacketInfoNeverPanic(f *testing.F) {
	f.Add(client(1))
	f.Add(make([]byte, 24))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, _ := ParseDHCP(b, testMAC)
		DHCPReply(r, [4]byte{10, 77, 123, 1}, [4]byte{10, 77, 123, 2})
		PacketInterface(b)
	})
}

func TestStandaloneGatewayIsOptionalAndLocalOnly(t *testing.T) {
	server, peer := [4]byte{10, 6, 9, 1}, [4]byte{10, 6, 9, 2}
	for _, kind := range []byte{1, 3} {
		r := Request{Kind: kind, MAC: [6]byte{1, 2, 3, 4, 5, 6}}
		if kind == 3 {
			r.HasRequested = true
			r.Requested = peer
		}
		for _, enabled := range []bool{false, true} {
			b, k := DHCPReplyWithRouter(r, server, peer, enabled)
			if len(b) < 300 || k == 0 {
				t.Fatal("missing reply")
			}
			found := false
			for i := 240; i < len(b) && b[i] != 255; {
				if b[i] == 0 {
					i++
					continue
				}
				code, n := b[i], int(b[i+1])
				v := b[i+2 : i+2+n]
				if code == 6 {
					t.Fatal("unexpected DNS")
				}
				if code == 3 {
					found = true
					if n != 4 || !bytes.Equal(v, server[:]) {
						t.Fatal("nonlocal gateway")
					}
				}
				i += 2 + n
			}
			if found != enabled {
				t.Fatal("gateway preference ignored")
			}
		}
	}
}
