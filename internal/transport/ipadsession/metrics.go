package ipadsession

import (
	"encoding/binary"
	"net"
)

type Traffic struct {
	ReceivedBytes    uint64  `json:"received_bytes"`
	SentBytes        uint64  `json:"sent_bytes"`
	ReceiveMbps      float64 `json:"receive_mbps"`
	TransmitMbps     float64 `json:"transmit_mbps"`
	PeakReceiveMbps  float64 `json:"peak_receive_mbps"`
	PeakTransmitMbps float64 `json:"peak_transmit_mbps"`
	CounterResets    uint32  `json:"counter_resets"`
	Samples          uint64  `json:"samples"`
}

func (t *Traffic) Add(prevIn, prevOut, nextIn, nextOut uint64, seconds float64) {
	t.ReceiveMbps, t.TransmitMbps = 0, 0
	if seconds <= 0 {
		return
	}
	t.Samples++
	if nextIn < prevIn || nextOut < prevOut {
		t.CounterResets++
		return
	}
	in, out := nextIn-prevIn, nextOut-prevOut
	t.ReceivedBytes += in
	t.SentBytes += out
	t.ReceiveMbps = float64(in) * 8 / seconds / 1e6
	t.TransmitMbps = float64(out) * 8 / seconds / 1e6
	t.PeakReceiveMbps = max(t.PeakReceiveMbps, t.ReceiveMbps)
	t.PeakTransmitMbps = max(t.PeakTransmitMbps, t.TransmitMbps)
}

// Exact address pair and native link-local scope, never friendly names or PID.
// MIB_TCPROW_OWNER_PID=24, MIB_TCP6ROW_OWNER_PID=56, table DWORD count.
func SunshineTCP(table []byte, ipv6 bool, local, peer net.IP, scope uint32) (bool, bool) {
	stride := 24
	if ipv6 {
		stride = 56
	}
	if len(table) < 4 {
		return false, false
	}
	n := binary.LittleEndian.Uint32(table[:4])
	if n > 16384 || uint64(n)*uint64(stride) > uint64(len(table)-4) {
		return false, false
	}
	for i := uint32(0); i < n; i++ {
		r := table[4+int(i)*stride : 4+int(i+1)*stride]
		var state uint32
		var port uint16
		var a, b net.IP
		if ipv6 {
			a, b = net.IP(r[:16]), net.IP(r[24:40])
			state = binary.LittleEndian.Uint32(r[48:52])
			port = binary.BigEndian.Uint16(r[20:22])
			if scope == 0 || binary.LittleEndian.Uint32(r[16:20]) != scope || binary.LittleEndian.Uint32(r[40:44]) != scope {
				continue
			}
		} else {
			a, b = net.IP(r[4:8]), net.IP(r[12:16])
			state = binary.LittleEndian.Uint32(r[:4])
			port = binary.BigEndian.Uint16(r[8:10])
		}
		if state == 5 && (port == 47984 || port == 47989 || port == 48010) && a.Equal(local) && b.Equal(peer) {
			return true, true
		}
	}
	return false, true
}

func USBSpeedLabel(legacy byte, v2 bool, flags uint32) string {
	if !v2 {
		return "尚未確認 USB 3.x 協商速率"
	}
	if flags&4 != 0 {
		return "USB SuperSpeedPlus（10 Gbps 或更高級別）"
	}
	if flags&1 != 0 {
		return "USB SuperSpeed（5 Gbps 級別）"
	}
	switch legacy {
	case 0:
		return "USB LowSpeed（1.5 Mbps）"
	case 1:
		return "USB FullSpeed（12 Mbps）"
	case 2:
		return "USB HighSpeed（480 Mbps）"
	}
	return "USB 協商速率未報告"
}
