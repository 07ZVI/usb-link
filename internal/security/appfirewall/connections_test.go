package appfirewall

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestTCPNativeLayoutIPv4(t *testing.T) {
	b := make([]byte, 52)
	binary.LittleEndian.PutUint32(b, 2)
	r := b[4:28]
	binary.LittleEndian.PutUint32(r, 5)
	copy(r[4:8], net.ParseIP("10.6.9.1").To4())
	binary.BigEndian.PutUint16(r[8:10], 10690)
	copy(r[12:16], net.ParseIP("10.6.9.2").To4())
	binary.BigEndian.PutUint16(r[16:18], 52000)
	binary.LittleEndian.PutUint32(r[20:24], 1234)
	binary.LittleEndian.PutUint32(b[28:32], 2)
	v, err := ParseTCP(b, false)
	if err != nil || len(v) != 1 || v[0].PID != 1234 || v[0].Local != "10.6.9.1:10690" || v[0].Remote != "10.6.9.2:52000" {
		t.Fatal(v, err)
	}
}
func TestTCPNativeLayoutIPv6Scope(t *testing.T) {
	b := make([]byte, 60)
	binary.LittleEndian.PutUint32(b, 1)
	r := b[4:]
	copy(r[:16], net.ParseIP("fe80::1").To16())
	copy(r[24:40], net.ParseIP("fe80::2").To16())
	binary.LittleEndian.PutUint32(r[16:20], 5)
	binary.LittleEndian.PutUint32(r[40:44], 6)
	binary.BigEndian.PutUint16(r[20:22], 443)
	binary.BigEndian.PutUint16(r[44:46], 10690)
	binary.LittleEndian.PutUint32(r[48:52], 5)
	binary.LittleEndian.PutUint32(r[52:56], 77)
	v, err := ParseTCP(b, true)
	if err != nil || len(v) != 1 || v[0].Local != "[fe80::1%5]:443" || v[0].Remote != "[fe80::2%6]:10690" || v[0].PID != 77 {
		t.Fatal(v, err)
	}
}
func TestTCPMalformedTablesFail(t *testing.T) {
	for _, b := range [][]byte{nil, {1, 0, 0}, {1, 0, 0, 0}, {0xff, 0xff, 0xff, 0xff}} {
		if _, err := ParseTCP(b, false); err == nil {
			t.Fatal("malformed table accepted")
		}
	}
}
