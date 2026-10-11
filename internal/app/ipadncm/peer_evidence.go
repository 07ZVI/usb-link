package ipadncm

import (
	"bytes"
	"encoding/binary"
	"net"
)

// SDK IPV6_ADDRESS_EX is packed(1): port2 + flow4 + address16 + scope4 =26.
// Its enclosing ICMPV6_ECHO_REPLY_LH aligns Status to28, RTT to32, body to36.
// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/NetworkManagement/IpHelper/struct.IPV6_ADDRESS_EX.html
const (
	echoAddressOffset = 6
	echoScopeOffset   = 22
	echoStatusOffset  = 28
	echoRTTOffset     = 32
	echoBodyOffset    = 36
)

type echoReplyEvidence struct {
	IP               net.IP
	ScopeLE, ScopeBE uint32
	Status, RTT      uint32
	NonceMatches     bool
	Valid            bool
	Error            string
}

// This validates reply contents, not interface identity. A zero reply scope is
// recorded as unreported, never as a matching interface. The caller must bind
// BOTH request sockaddrs to the live source/scope and recheck the same exact USB
// root/GUID/LUID/source/scope before and after the request before accepting a
// scoped roundtrip. Any contradictory nonzero reply scope is rejected.
func parseEchoReply(buf, nonce []byte, source, destination net.IP, scope uint32, multicast bool) echoReplyEvidence {
	r := echoReplyEvidence{}
	if scope == 0 || len(nonce) != 32 || !eligibleIPv6Peer(source, nil) ||
		(!multicast && !eligibleIPv6Peer(destination, source)) ||
		(multicast && !destination.Equal(net.ParseIP("ff02::1"))) {
		r.Error = "ECHO_SCOPE_OR_ADDRESS_INVALID"
		return r
	}
	if len(buf) < echoBodyOffset+len(nonce) {
		r.Error = "ECHO_REPLY_TRUNCATED"
		return r
	}
	r.IP = net.IP(append([]byte(nil), buf[echoAddressOffset:echoScopeOffset]...))
	r.ScopeLE = binary.LittleEndian.Uint32(buf[echoScopeOffset : echoScopeOffset+4])
	r.ScopeBE = binary.BigEndian.Uint32(buf[echoScopeOffset : echoScopeOffset+4])
	r.Status = binary.LittleEndian.Uint32(buf[echoStatusOffset : echoStatusOffset+4])
	r.RTT = binary.LittleEndian.Uint32(buf[echoRTTOffset : echoRTTOffset+4])
	r.NonceMatches = bytes.Equal(buf[echoBodyOffset:echoBodyOffset+len(nonce)], nonce)
	switch {
	case r.Status != 0:
		r.Error = "ECHO_REPLY_STATUS_NOT_SUCCESS"
	case !eligibleIPv6Peer(r.IP, source):
		r.Error = "ECHO_REPLIER_NOT_NONLOCAL_LINK_LOCAL"
	case !multicast && !r.IP.Equal(destination):
		r.Error = "ECHO_REPLIER_NOT_REQUESTED_PEER"
	case r.ScopeLE != 0 && r.ScopeLE != scope && r.ScopeBE != scope:
		r.Error = "ECHO_REPLY_SCOPE_CONTRADICTS_REQUEST"
	case !r.NonceMatches:
		r.Error = "ECHO_NONCE_PAYLOAD_MISMATCH"
	default:
		r.Valid = true
	}
	return r
}

func eligibleIPv6Peer(ip net.IP, source net.IP) bool {
	return ip != nil && ip.To4() == nil && ip.IsLinkLocalUnicast() && !ip.Equal(source)
}
