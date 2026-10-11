// Package rawusb implements fixed, nonce-scoped USB-only test datagrams.
package rawusb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"suhang/usbnet/internal/transport/ncm"
)

const Port = 47780
const Header = 40
const InputIPLength = 8000 // Below macOS's default UDP maxdgram=9216; no sysctl change.
const flows = 4
const sequenceBits = 1 << 24

var magic = [8]byte{'U', 'S', 'B', 'R', 'A', 'W', '4', '9'}
var be = binary.BigEndian

// Command accepts only these fixed operations; no addresses/ports are supplied.
func Command(kind string) (direction, profile string, closed bool, ok bool) {
	switch kind {
	case "RAWOUT", "RAWOUTCPU", "RAWOUTTRACE", "RAWCLOSED", "RAWCLOSEDCPU", "RAWCLOSEDTRACE":
		direction = "windows_to_mac"
		closed = kind == "RAWCLOSED" || kind == "RAWCLOSEDCPU" || kind == "RAWCLOSEDTRACE"
	case "RAWIN", "RAWINCPU", "RAWINTRACE":
		direction = "mac_to_windows"
	default:
		return "", "", false, false
	}
	if kind[len(kind)-3:] == "CPU" {
		profile = "CPU"
	}
	if len(kind) >= 5 && kind[len(kind)-5:] == "TRACE" {
		profile = "TRACE"
	}
	return direction, profile, closed, true
}

func Payload(ipLength int, nonce [16]byte, flow byte) ([]byte, error) {
	if ipLength < 1500 || ipLength > 16000 || flow >= flows {
		return nil, fmt.Errorf("raw packet limits")
	}
	p := make([]byte, ipLength-28)
	for i := Header; i < len(p); i++ {
		p[i] = byte(i % 251)
	}
	copy(p, magic[:])
	copy(p[8:24], nonce[:])
	p[32] = flow
	return p, nil
}
func Sequence(p []byte, seq uint64) { be.PutUint64(p[24:32], seq) }
func Identity(p []byte, nonce [16]byte) (uint64, byte, bool) {
	if len(p) < Header || !bytes.Equal(p[:8], magic[:]) || !bytes.Equal(p[8:24], nonce[:]) || p[32] >= flows {
		return 0, 0, false
	}
	return be.Uint64(p[24:32]), p[32], true
}

// IPv4 UDP checksum zero is permitted; this keeps generation out of the CPU test.
// The IPv4 header is checksummed and DF is set. No fragmentation is generated.
func Frame(ipLength int, nonce [16]byte, mac [6]byte) ([]byte, error) {
	p, err := Payload(ipLength, nonce, 0)
	if err != nil {
		return nil, err
	}
	if mac == [6]byte{} || mac[0]&1 != 0 {
		return nil, fmt.Errorf("unresolved raw peer")
	}
	b := make([]byte, 14+ipLength)
	copy(b[:6], mac[:])
	copy(b[6:12], ncm.ProbeMAC[:])
	be.PutUint16(b[12:14], 0x800)
	ip := b[14:]
	ip[0] = 0x45
	be.PutUint16(ip[2:4], uint16(ipLength))
	be.PutUint16(ip[6:8], 0x4000)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], ncm.WindowsIP[:])
	copy(ip[16:20], ncm.MacIP[:])
	be.PutUint16(ip[10:12], ncm.Checksum(ip[:20]))
	be.PutUint16(ip[20:22], Port)
	be.PutUint16(ip[22:24], Port)
	be.PutUint16(ip[24:26], uint16(ipLength-20))
	copy(ip[28:], p)
	return b, nil
}
func FrameSequence(frame []byte, seq uint64) { Sequence(frame[42:], seq) }

// Input identifies only the current test's fixed USB peer, UDP tuple and nonce.
// UDP payload checksum work is intentionally excluded from the raw counter.
func Input(f []byte, nonce [16]byte, mac [6]byte) ([]byte, bool) {
	if len(f) < 42+Header || !bytes.Equal(f[:6], ncm.ProbeMAC[:]) || !bytes.Equal(f[6:12], mac[:]) || be.Uint16(f[12:14]) != 0x800 {
		return nil, false
	}
	ip := f[14:]
	n := int(be.Uint16(ip[2:4]))
	if ip[0] != 0x45 || ip[9] != 17 || n != InputIPLength || n > len(ip) || be.Uint16(ip[6:8])&0xbfff != 0 || ncm.Checksum(ip[:20]) != 0 || !bytes.Equal(ip[12:16], ncm.MacIP[:]) || !bytes.Equal(ip[16:20], ncm.WindowsIP[:]) {
		return nil, false
	}
	if port := be.Uint16(ip[20:22]); port < Port+1 || port > Port+flows {
		return nil, false
	}
	if be.Uint16(ip[22:24]) != Port || int(be.Uint16(ip[24:26])) != n-20 {
		return nil, false
	}
	p := ip[28:n]
	_, flow, ok := Identity(p, nonce)
	if !ok || be.Uint16(ip[20:22]) != Port+1+uint16(flow) {
		return nil, false
	}
	return p, true
}
