package bridge

import "encoding/binary"

// Counts only already-validated IP packets. No addresses, payloads or per-packet
// allocations are retained. The owner publishes this value with its counters.
type PacketProfile struct {
	Lengths                                    [5]uint64 // <=1500, <=2000, <=9000, <=16000, larger
	Fragments, TCPData, TCPACKOnly             uint64
	TCPDataBytes, MSSObserved                  uint64
	MaxIPLength, MaxTCPPayload, MSSMin, MSSMax uint32
}

func (p *PacketProfile) Observe(ip []byte) {
	p.MaxIPLength = max(p.MaxIPLength, uint32(len(ip)))
	for i, n := range [...]int{1500, 2000, 9000, 16000, 65535} {
		if len(ip) <= n {
			p.Lengths[i]++
			break
		}
	}
	if len(ip) < 20 {
		return
	}
	if binary.BigEndian.Uint16(ip[6:8])&0x3fff != 0 {
		p.Fragments++
		return
	}
	h := int(ip[0]&15) * 4
	if ip[9] != 6 || h < 20 || h+20 > len(ip) {
		return
	}
	t := ip[h:]
	th := int(t[12]>>4) * 4
	if th < 20 || th > len(t) {
		return
	}
	if th < len(t) {
		p.TCPData++
		payload := uint32(len(t) - th)
		p.TCPDataBytes += uint64(payload)
		p.MaxTCPPayload = max(p.MaxTCPPayload, payload)
	} else if t[13] == 0x10 {
		p.TCPACKOnly++
	}
	if t[13]&2 == 0 {
		return
	}
	for options := t[20:th]; len(options) > 0; {
		kind := options[0]
		if kind == 0 {
			break
		}
		if kind == 1 {
			options = options[1:]
			continue
		}
		if len(options) < 2 || options[1] < 2 || int(options[1]) > len(options) {
			break
		}
		if kind == 2 && options[1] == 4 {
			mss := uint32(binary.BigEndian.Uint16(options[2:4]))
			if mss > 0 {
				if p.MSSObserved == 0 {
					p.MSSMin = mss
				} else {
					p.MSSMin = min(p.MSSMin, mss)
				}
				p.MSSMax = max(p.MSSMax, mss)
				p.MSSObserved++
			}
		}
		options = options[int(options[1]):]
	}
}
