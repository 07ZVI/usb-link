package appfirewall

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// TCP tables are connection observations, not interception events. They cannot
// prove whether a connection originated inbound/outbound or reconstruct UDP.
type Connection struct {
	PID      uint32 `json:"pid"`
	Path     string `json:"path"`
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	State    uint32 `json:"state"`
	Protocol string `json:"protocol"`
}

func ParseTCP(b []byte, v6 bool) ([]Connection, error) {
	stride := 24
	if v6 {
		stride = 56
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("TCP_TABLE_INVALID")
	}
	n := binary.LittleEndian.Uint32(b)
	if n > 16384 || uint64(n)*uint64(stride) > uint64(len(b)-4) {
		return nil, fmt.Errorf("TCP_TABLE_INVALID")
	}
	out := []Connection{}
	for i := uint32(0); i < n; i++ {
		r := b[4+int(i)*stride : 4+int(i+1)*stride]
		c := Connection{Protocol: "TCP"}
		var local, remote net.IP
		var lp, rp uint16
		var ls, rs uint32
		if v6 {
			local = net.IP(r[:16])
			remote = net.IP(r[24:40])
			lp = binary.BigEndian.Uint16(r[20:22])
			rp = binary.BigEndian.Uint16(r[44:46])
			ls = binary.LittleEndian.Uint32(r[16:20])
			rs = binary.LittleEndian.Uint32(r[40:44])
			c.State = binary.LittleEndian.Uint32(r[48:52])
			c.PID = binary.LittleEndian.Uint32(r[52:56])
		} else {
			local = net.IP(r[4:8])
			remote = net.IP(r[12:16])
			lp = binary.BigEndian.Uint16(r[8:10])
			rp = binary.BigEndian.Uint16(r[16:18])
			c.State = binary.LittleEndian.Uint32(r[:4])
			c.PID = binary.LittleEndian.Uint32(r[20:24])
		}
		if c.State == 2 || rp == 0 {
			continue
		} // Listening endpoints are not connections.
		l, rmt := local.String(), remote.String()
		if ls != 0 && local.IsLinkLocalUnicast() {
			l += "%" + strconv.FormatUint(uint64(ls), 10)
		}
		if rs != 0 && remote.IsLinkLocalUnicast() {
			rmt += "%" + strconv.FormatUint(uint64(rs), 10)
		}
		c.Local = net.JoinHostPort(l, strconv.Itoa(int(lp)))
		c.Remote = net.JoinHostPort(rmt, strconv.Itoa(int(rp)))
		out = append(out, c)
	}
	return out, nil
}
