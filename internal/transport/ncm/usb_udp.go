package ncm

import "bytes"

// USBUDPRequest validates a fixed, unfragmented point-to-point IPv4/UDP packet.
// It is not a router: only the explicit USB addresses, MAC and one port pass.
func USBUDPRequest(f []byte, port uint16) ([]byte, [6]byte, bool) {
	e, err := ParseEthernet(f)
	if err != nil || e.Type != 0x800 || e.Destination != ProbeMAC || e.Source == [6]byte{} || e.Source[0]&1 != 0 {
		return nil, [6]byte{}, false
	}
	ip := e.Payload
	if len(ip) < 28 || ip[0] != 0x45 || ip[9] != 17 || be.Uint16(ip[6:])&0xbfff != 0 {
		return nil, e.Source, false
	}
	n := int(be.Uint16(ip[2:]))
	if n < 28 || n > len(ip) || Checksum(ip[:20]) != 0 {
		return nil, e.Source, false
	}
	ip = ip[:n]
	if !bytes.Equal(ip[12:16], MacIP[:]) || !bytes.Equal(ip[16:20], WindowsIP[:]) || be.Uint16(ip[20:]) != port || be.Uint16(ip[22:]) != port || int(be.Uint16(ip[24:])) != n-20 {
		return nil, e.Source, false
	}
	if be.Uint16(ip[26:]) != 0 {
		pseudo := make([]byte, 12+n-20)
		copy(pseudo, ip[12:20])
		pseudo[9] = 17
		be.PutUint16(pseudo[10:], uint16(n-20))
		copy(pseudo[12:], ip[20:])
		if Checksum(pseudo) != 0 {
			return nil, e.Source, false
		}
	}
	return ip[28:], e.Source, true
}

func USBUDPFrame(payload []byte, mac [6]byte, port uint16) []byte {
	if len(payload) > 1400 || mac == [6]byte{} || mac[0]&1 != 0 {
		return nil
	}
	b := make([]byte, 28+len(payload))
	b[0] = 0x45
	be.PutUint16(b[2:], uint16(len(b)))
	b[8] = 64
	b[9] = 17
	copy(b[12:], WindowsIP[:])
	copy(b[16:], MacIP[:])
	be.PutUint16(b[10:], Checksum(b[:20]))
	be.PutUint16(b[20:], port)
	be.PutUint16(b[22:], port)
	be.PutUint16(b[24:], uint16(len(b)-20))
	copy(b[28:], payload)
	pseudo := make([]byte, 12+len(b)-20)
	copy(pseudo, b[12:20])
	pseudo[9] = 17
	be.PutUint16(pseudo[10:], uint16(len(b)-20))
	copy(pseudo[12:], b[20:])
	check := Checksum(pseudo)
	if check == 0 {
		check = 65535
	}
	be.PutUint16(b[26:], check)
	return Frame(mac, ProbeMAC, 0x800, b)
}
