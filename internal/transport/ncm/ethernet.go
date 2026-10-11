package ncm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

var be = binary.BigEndian
var MacIP = [4]byte{10, 77, 0, 1}
var WindowsIP = [4]byte{10, 77, 0, 2}
var ProbeMAC = [6]byte{2, 0x53, 0x55, 0x48, 0, 2}

type Ethernet struct {
	Destination, Source [6]byte
	Type                uint16
	Payload             []byte
}

func ParseEthernet(f []byte) (Ethernet, error) {
	var e Ethernet
	if len(f) < 14 {
		return e, fmt.Errorf("short Ethernet frame")
	}
	copy(e.Destination[:], f)
	copy(e.Source[:], f[6:])
	e.Type = be.Uint16(f[12:])
	e.Payload = f[14:]
	return e, nil
}
func Frame(dst, src [6]byte, t uint16, p []byte) []byte {
	return FrameInto(nil, dst, src, t, p)
}

// FrameInto reuses non-aliasing caller storage. Consume the result before
// reusing that storage; Ethernet padding is reset even after a longer frame.
func FrameInto(storage []byte, dst, src [6]byte, t uint16, p []byte) []byte {
	n := max(60, 14+len(p))
	b := storage
	if cap(b) < n {
		b = make([]byte, n)
	} else {
		b = b[:n]
		clear(b[14+len(p):])
	}
	copy(b, dst[:])
	copy(b[6:], src[:])
	be.PutUint16(b[12:], t)
	copy(b[14:], p)
	return b
}
func (e Ethernet) Summary() string {
	return fmt.Sprintf("type=0x%04x src=%s dst=%s bytes=%d", e.Type, net.HardwareAddr(e.Source[:]), net.HardwareAddr(e.Destination[:]), len(e.Payload)+14)
}

// ARPReply answers only IPv4 Ethernet requests for this probe's address.
func ARPReply(f []byte) ([]byte, [6]byte, error) {
	var mac [6]byte
	e, err := ParseEthernet(f)
	if err != nil {
		return nil, mac, err
	}
	a := e.Payload
	if e.Type != 0x806 || len(a) < 28 || be.Uint16(a) != 1 || be.Uint16(a[2:]) != 0x800 || a[4] != 6 || a[5] != 4 || be.Uint16(a[6:]) != 1 || !bytes.Equal(a[24:28], WindowsIP[:]) || !bytes.Equal(a[14:18], MacIP[:]) {
		return nil, mac, nil
	}
	copy(mac[:], a[8:14])
	if mac != e.Source || mac[0]&1 != 0 || mac == [6]byte{} {
		return nil, mac, fmt.Errorf("invalid ARP sender")
	}
	b := make([]byte, 28)
	copy(b, a[:8])
	be.PutUint16(b[6:], 2)
	copy(b[8:], ProbeMAC[:])
	copy(b[14:], WindowsIP[:])
	copy(b[18:], mac[:])
	copy(b[24:], MacIP[:])
	return Frame(mac, ProbeMAC, 0x806, b), mac, nil
}
func Checksum(b []byte) uint16 {
	var s uint32
	for len(b) >= 2 {
		s += uint32(be.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		s += uint32(b[0]) << 8
	}
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	return ^uint16(s)
}
func EchoRequest(dst [6]byte, sequence uint16) []byte {
	payload := []byte("SUHANG-USB-NCM-PROBE")
	b := make([]byte, 28+len(payload))
	b[0] = 0x45
	be.PutUint16(b[2:], uint16(len(b)))
	be.PutUint16(b[4:], sequence)
	b[8] = 64
	b[9] = 1
	copy(b[12:], WindowsIP[:])
	copy(b[16:], MacIP[:])
	be.PutUint16(b[10:], Checksum(b[:20]))
	b[20] = 8
	be.PutUint16(b[24:], 0x5355)
	be.PutUint16(b[26:], sequence)
	copy(b[28:], payload)
	be.PutUint16(b[22:], Checksum(b[20:]))
	return Frame(dst, ProbeMAC, 0x800, b)
}
func IPv4ICMP(f []byte) (Ethernet, []byte, error) {
	e, err := ParseEthernet(f)
	if err != nil {
		return e, nil, err
	}
	b := e.Payload
	if e.Type != 0x800 || len(b) < 20 || b[0]>>4 != 4 {
		return e, nil, nil
	}
	h := int(b[0]&15) * 4
	n := int(be.Uint16(b[2:]))
	if h < 20 || n < h+8 || n > len(b) || b[9] != 1 || be.Uint16(b[6:])&0x3fff != 0 {
		return e, nil, nil
	}
	b = b[:n]
	if Checksum(b[:h]) != 0 || Checksum(b[h:]) != 0 {
		return e, nil, fmt.Errorf("invalid IP/ICMP checksum")
	}
	return e, b, nil
}
func EchoReply(f []byte) []byte {
	e, b, err := IPv4ICMP(f)
	if err != nil || b == nil || b[int(b[0]&15)*4] != 8 || b[int(b[0]&15)*4+1] != 0 || !bytes.Equal(b[12:16], MacIP[:]) || !bytes.Equal(b[16:20], WindowsIP[:]) {
		return nil
	}
	b = append([]byte(nil), b...)
	h := int(b[0]&15) * 4
	copy(b[12:], WindowsIP[:])
	copy(b[16:], MacIP[:])
	b[8] = 64
	b[10] = 0
	b[11] = 0
	be.PutUint16(b[10:], Checksum(b[:h]))
	b[h] = 0
	b[h+2] = 0
	b[h+3] = 0
	be.PutUint16(b[h+2:], Checksum(b[h:]))
	return Frame(e.Source, ProbeMAC, 0x800, b)
}
func IsProbeEchoReply(f []byte, sequence uint16) bool {
	_, b, e := IPv4ICMP(f)
	if e != nil || b == nil {
		return false
	}
	h := int(b[0]&15) * 4
	return bytes.Equal(b[12:16], MacIP[:]) && bytes.Equal(b[16:20], WindowsIP[:]) && b[h] == 0 && b[h+1] == 0 && be.Uint16(b[h+4:]) == 0x5355 && be.Uint16(b[h+6:]) == sequence && bytes.Equal(b[h+8:], []byte("SUHANG-USB-NCM-PROBE"))
}
