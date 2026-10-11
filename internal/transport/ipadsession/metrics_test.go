package ipadsession

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestTrafficKeepsPeakAfterStreamStopsAndRejectsReset(t *testing.T) {
	var v Traffic
	v.Add(0, 0, 1000, 50000000, 1)
	v.Add(1000, 50000000, 1001, 50000001, 1)
	if v.PeakTransmitMbps != 400 || v.SentBytes != 50000001 || v.TransmitMbps >= 1 {
		t.Fatal(v)
	}
	v.Add(1001, 50000001, 1, 1, 1)
	if v.CounterResets != 1 || v.PeakTransmitMbps != 400 || v.SentBytes != 50000001 {
		t.Fatal(v)
	}
}
func TestExactSunshineTCPNativeTable(t *testing.T) {
	b := make([]byte, 28)
	binary.LittleEndian.PutUint32(b, 1)
	binary.LittleEndian.PutUint32(b[4:], 5)
	copy(b[8:12], net.ParseIP("10.6.9.1").To4())
	copy(b[16:20], net.ParseIP("10.6.9.2").To4())
	binary.BigEndian.PutUint16(b[12:14], 47989)
	a, p := net.ParseIP("10.6.9.1"), net.ParseIP("10.6.9.2")
	if ok, valid := SunshineTCP(b, false, a, p, 0); !ok || !valid {
		t.Fatal("native tuple missed")
	}
	if ok, _ := SunshineTCP(b, false, a, net.ParseIP("192.168.1.2"), 0); ok {
		t.Fatal("other peer")
	}
	if _, valid := SunshineTCP(b[:25], false, a, p, 0); valid {
		t.Fatal("truncated table")
	}
	c := make([]byte, 60)
	binary.LittleEndian.PutUint32(c, 1)
	copy(c[4:20], net.ParseIP("fe80::1").To16())
	binary.LittleEndian.PutUint32(c[20:24], 25)
	binary.BigEndian.PutUint16(c[24:26], 48010)
	copy(c[28:44], net.ParseIP("fe80::2").To16())
	binary.LittleEndian.PutUint32(c[44:48], 25)
	binary.LittleEndian.PutUint32(c[52:56], 5)
	if ok, v := SunshineTCP(c, true, net.ParseIP("fe80::1"), net.ParseIP("fe80::2"), 25); !ok || !v {
		t.Fatal("native scoped IPv6 missed")
	}
	if ok, _ := SunshineTCP(c, true, net.ParseIP("fe80::1"), net.ParseIP("fe80::2"), 26); ok {
		t.Fatal("other scope")
	}
}
func TestUSBSpeedDoesNotConfuseCapabilityAndOperation(t *testing.T) {
	if strings.Contains(USBSpeedLabel(2, false, 0), "480") {
		t.Fatal("legacy ceiling inferred")
	}
	if !strings.Contains(USBSpeedLabel(2, true, 2), "480") || !strings.Contains(USBSpeedLabel(2, true, 3), "5 Gbps") {
		t.Fatal("capability mistaken for operation")
	}
}
