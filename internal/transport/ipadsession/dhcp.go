// Package ipadsession provides the bounded single-peer USB application trial.
package ipadsession

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
)

// Request deliberately omits device names, client identifiers and raw options.
type Request struct {
	Kind                    byte
	XID                     [4]byte
	MAC                     [6]byte
	CI                      [4]byte
	Requested               [4]byte
	Server                  [4]byte
	HasRequested, HasServer bool
	ClientID                []byte // private, echoed only; never included in diagnostics
}

func ParseDHCP(b []byte, expected [6]byte) (Request, error) {
	var r Request
	if len(b) < 240 || len(b) > 2048 || b[0] != 1 || b[1] != 1 || b[2] != 6 || b[3] != 0 ||
		!bytes.Equal(b[24:28], make([]byte, 4)) || !bytes.Equal(b[236:240], []byte{99, 130, 83, 99}) ||
		!bytes.Equal(b[28:34], expected[:]) {
		return r, errors.New("not the verified direct Ethernet DHCP peer")
	}
	copy(r.XID[:], b[4:8])
	copy(r.MAC[:], b[28:34])
	copy(r.CI[:], b[12:16])
	seen := map[byte]bool{}
	ended := false
	for i := 240; i < len(b); {
		kind := b[i]
		i++
		if kind == 255 {
			ended = true
			break
		}
		if kind == 0 {
			continue
		}
		if i >= len(b) {
			return r, errors.New("truncated option")
		}
		n := int(b[i])
		i++
		if n == 0 || i+n > len(b) {
			return r, errors.New("invalid option")
		}
		v := b[i : i+n]
		i += n
		// Duplicated critical options and option overload are not supported.
		if kind == 52 {
			return r, errors.New("option overload not supported")
		}
		switch kind {
		case 53, 50, 54, 61:
			if seen[kind] {
				return r, errors.New("ambiguous option")
			}
			seen[kind] = true
		}
		switch kind {
		case 53:
			if n != 1 {
				return r, errors.New("message type length")
			}
			r.Kind = v[0]
		case 50:
			if n != 4 {
				return r, errors.New("requested IP length")
			}
			copy(r.Requested[:], v)
			r.HasRequested = true
		case 54:
			if n != 4 {
				return r, errors.New("server IP length")
			}
			copy(r.Server[:], v)
			r.HasServer = true
		case 61:
			if n > 128 {
				return r, errors.New("client ID limit")
			}
			r.ClientID = append([]byte(nil), v...)
		}
	}
	if !ended || !seen[53] {
		return r, errors.New("missing DHCP end or type")
	}
	return r, nil
}

// Reply only assigns one peer address. Never advertise a router/default route
// or DNS server. DECLINE is handled by the caller by stopping the trial.
func DHCPReply(r Request, server, peer [4]byte) ([]byte, byte) {
	return DHCPReplyWithRouter(r, server, peer, false)
}

// The optional router is this Windows endpoint, not Internet sharing. It is
// explicitly disclosed to the user because it changes the iPad's default route.
func DHCPReplyWithRouter(r Request, server, peer [4]byte, router bool) ([]byte, byte) {
	return DHCPReplyWithDNS(r, server, peer, router, false)
}

// DHCPReplyWithDNS advertises only the explicitly enabled USB Internet gateway.
func DHCPReplyWithDNS(r Request, server, peer [4]byte, router, dns bool) ([]byte, byte) {
	if r.HasServer && r.Server != server {
		return nil, 0
	}
	kind := byte(0)
	switch r.Kind {
	case 1:
		if r.CI != [4]byte{} {
			return nil, 0
		}
		kind = 2
	case 3:
		if r.HasRequested {
			if r.Requested != peer || r.CI != [4]byte{} {
				return nil, 0
			}
		} else if r.CI != peer {
			return nil, 0
		}
		kind = 5
	default:
		return nil, 0
	}
	b := make([]byte, 240)
	b[0] = 2
	b[1] = 1
	b[2] = 6
	copy(b[4:8], r.XID[:])
	copy(b[12:16], r.CI[:])
	copy(b[16:20], peer[:])
	copy(b[28:34], r.MAC[:])
	copy(b[236:], []byte{99, 130, 83, 99})
	opt := func(code byte, v []byte) { b = append(b, code, byte(len(v))); b = append(b, v...) }
	opt(53, []byte{kind})
	opt(54, server[:])
	opt(1, []byte{255, 255, 255, 0})
	if router {
		opt(3, server[:])
		if dns {
			opt(6, server[:])
		}
	}
	var lease [4]byte
	binary.BigEndian.PutUint32(lease[:], 300)
	opt(51, lease[:])
	binary.BigEndian.PutUint32(lease[:], 150)
	opt(58, lease[:])
	binary.BigEndian.PutUint32(lease[:], 262)
	opt(59, lease[:])
	if len(r.ClientID) > 0 {
		opt(61, r.ClientID)
	}
	b = append(b, 255)
	for len(b) < 300 {
		b = append(b, 0)
	}
	return b, kind
}

// Windows x64 WSACMSGHDR is size16, aligned8; IN_PKTINFO is address4/index4.
// Reject truncated ancillary messages, duplicates and absent target identity.
func PacketInterface(oob []byte) (uint32, bool) {
	var index uint32
	seen := false
	for len(oob) > 0 {
		if len(oob) < 16 {
			return 0, false
		}
		n := binary.LittleEndian.Uint64(oob[:8])
		if n < 16 || n > uint64(len(oob)) {
			return 0, false
		}
		level := binary.LittleEndian.Uint32(oob[8:12])
		kind := binary.LittleEndian.Uint32(oob[12:16])
		if level == 0 && kind == 19 {
			if seen || n != 24 {
				return 0, false
			}
			seen = true
			index = binary.LittleEndian.Uint32(oob[20:24])
		}
		aligned := (n + 7) &^ uint64(7)
		if aligned > uint64(len(oob)) {
			if n == uint64(len(oob)) {
				break
			}
			return 0, false
		}
		oob = oob[aligned:]
	}
	return index, seen && index != 0
}
func PacketControl(ip net.IP, index uint32) []byte {
	if ip.To4() == nil || index == 0 {
		return nil
	}
	b := make([]byte, 24)
	binary.LittleEndian.PutUint64(b[:8], 24)
	binary.LittleEndian.PutUint32(b[12:16], 19)
	copy(b[16:20], ip.To4())
	binary.LittleEndian.PutUint32(b[20:24], index)
	return b
}

// RFC3442 host route gives iPad a physical next hop for the single Windows
// service IP. The USB interface owns the helper; the host IP is not duplicated.
func DHCPReplyForPlan(r Request, p Plan, router bool) ([]byte, byte) {
	var local, peer [4]byte
	copy(local[:], net.ParseIP(p.LocalAddress()).To4())
	copy(peer[:], net.ParseIP(p.PeerIP()).To4())
	b, k := DHCPReplyWithRouter(r, local, peer, router)
	if b == nil || (p.Version != 5 && p.Version != 6) {
		return b, k
	}
	end := 240
	for end < len(b) && b[end] != 255 {
		if b[end] == 0 {
			end++
			continue
		}
		end += 2 + int(b[end+1])
	}
	route := []byte{32, 10, 6, 9, 1}
	route = append(route, local[:]...)
	if router {
		route = append(route, 0)
		route = append(route, local[:]...)
	}
	b = append(append(b[:end], 121, byte(len(route))), append(route, 255)...)
	for len(b) < 300 {
		b = append(b, 0)
	}
	return b, k
}
