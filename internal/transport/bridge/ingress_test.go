package bridge

import (
	"testing"

	"suhang/usbnet/internal/transport/ncm"
)

func macFrame(dst [6]byte, ip []byte) []byte {
	return ncm.Frame(dst, [6]byte{2, 0, 0, 0, 0, 9}, 0x800, ip)
}
func ipv4(total int, src, dst [4]byte) []byte {
	b := make([]byte, total)
	b[0] = 0x45
	b[2], b[3] = byte(total>>8), byte(total)
	b[8], b[9] = 64, 6
	copy(b[12:], src[:])
	copy(b[16:], dst[:])
	c := ncm.Checksum(b[:20])
	b[10], b[11] = byte(c>>8), byte(c)
	return b
}

func TestFromMacReasonMatchesFromMac(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
		want  DropReason
	}{
		{"accepted", macFrame(ncm.ProbeMAC, ipv4(1400, ncm.MacIP, ncm.WindowsIP)), DropNone},
		{"ipv6", ncm.Frame(ncm.ProbeMAC, [6]byte{2, 0, 0, 0, 0, 9}, 0x86dd, make([]byte, 40)), DropEtherType},
		{"other mac", macFrame([6]byte{2, 1, 1, 1, 1, 1}, ipv4(1400, ncm.MacIP, ncm.WindowsIP)), DropDestinationMAC},
		{"oversize", macFrame(ncm.ProbeMAC, ipv4(9000, ncm.MacIP, ncm.WindowsIP)), DropOversize},
		{"bad checksum", func() []byte { b := ipv4(100, ncm.MacIP, ncm.WindowsIP); b[10] ^= 1; return macFrame(ncm.ProbeMAC, b) }(), DropIPv4Invalid},
		{"foreign dst", macFrame(ncm.ProbeMAC, ipv4(100, ncm.MacIP, [4]byte{8, 8, 8, 8})), DropIPAddress},
		{"runt", []byte{1, 2, 3}, DropEthernet},
	}
	for _, c := range cases {
		p := Peer{MTU: 1500}
		_, ip, reason := p.FromMacReason(c.frame)
		q := Peer{MTU: 1500}
		_, ip2 := q.FromMac(c.frame)
		if reason != c.want || (ip == nil) != (ip2 == nil) || (c.want == DropNone) != (ip != nil) {
			t.Fatalf("%s: reason=%s want=%s ip=%v/%v", c.name, reason, c.want, ip != nil, ip2 != nil)
		}
	}
	p := Peer{MTU: 1500, MAC: [6]byte{2, 0, 0, 0, 0, 1}}
	if _, ip, r := p.FromMacReason(macFrame(ncm.ProbeMAC, ipv4(100, ncm.MacIP, ncm.WindowsIP))); ip != nil || r != DropPeerMAC {
		t.Fatalf("learned peer must reject other source: %s", r)
	}
}

func TestDropCountsAndIngressSnapshot(t *testing.T) {
	var d DropCounts
	d.Add(DropOversize)
	d.Add(DropOversize)
	d.Add(DropEtherType)
	if n := d.Named(); n["oversize"] != 2 || n["ethertype"] != 1 || len(n) != 2 {
		t.Fatalf("%v", n)
	}
	var c IngressCounters
	c.Submitted.Add(20)
	c.ObserveRead(16384, 16384, true)
	c.ObserveRead(100, 16384, false)
	c.ObserveQueue(7)
	c.ObserveQueue(3)
	s := c.Snapshot()
	if s.Outstanding != 18 || s.FullReads != 1 || s.ShortReads != 1 || s.ReadyImmediately != 1 || s.WaitedForIO != 1 || s.MaxQueue != 7 || s.Bytes != 16484 || s.MaxRead != 16384 {
		t.Fatalf("%+v", s)
	}
}

func BenchmarkFromMacTCPData(b *testing.B) {
	p := Peer{MTU: 9000}
	frame := macFrame(ncm.ProbeMAC, ipv4(8960, ncm.MacIP, ncm.WindowsIP))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ip := p.FromMac(frame); ip == nil {
			b.Fatal("dropped")
		}
	}
}
