package ipadncm

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
)

// Fixed SDK-layout fixture, independent of parser constants. Address starts at
// byte6; scope at22; nonzero padding at26 must never enter scope interpretation.
func packedEchoFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	b, err := hex.DecodeString("000000000000fe80000000000000040b7690e7c4850719000000dead0000000007000000")
	if err != nil || len(b) != 36 {
		t.Fatal(err, len(b))
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	return append(b, nonce...), nonce
}

func TestPackedSDKEchoReplyAddressScopePaddingAndBody(t *testing.T) {
	source, peer := net.ParseIP("fe80::1"), net.ParseIP("fe80::40b:7690:e7c4:8507")
	good, nonce := packedEchoFixture(t)
	r := parseEchoReply(good, nonce, source, peer, 25, false)
	if !r.Valid || !r.IP.Equal(peer) || r.RTT != 7 || r.ScopeLE != 25 || !r.NonceMatches {
		t.Fatal(r)
	}
	if net.IP(good[8:24]).String() != "::40b:7690:e7c4:8507:1900" {
		t.Fatal("fixture not sensitive to previous bug")
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
		error  string
	}{
		{"truncated", func(b []byte) []byte { return b[:67] }, "ECHO_REPLY_TRUNCATED"},
		{"local", func(b []byte) []byte { copy(b[6:22], source.To16()); return b }, "ECHO_REPLIER_NOT_NONLOCAL_LINK_LOCAL"},
		{"other_peer", func(b []byte) []byte { copy(b[6:22], net.ParseIP("fe80::3").To16()); return b }, "ECHO_REPLIER_NOT_REQUESTED_PEER"},
		{"other_scope", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[22:26], 26); return b }, "ECHO_REPLY_SCOPE_CONTRADICTS_REQUEST"},
		{"error_status", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[28:32], 11010); return b }, "ECHO_REPLY_STATUS_NOT_SUCCESS"},
		{"wrong_nonce", func(b []byte) []byte { b[36] ^= 1; return b }, "ECHO_NONCE_PAYLOAD_MISMATCH"},
		{"old_aligned_layout", func(b []byte) []byte {
			clear(b[:36])
			copy(b[8:24], peer.To16())
			binary.LittleEndian.PutUint32(b[24:28], 25)
			return b
		}, "ECHO_REPLIER_NOT_NONLOCAL_LINK_LOCAL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := parseEchoReply(tc.mutate(append([]byte(nil), good...)), nonce, source, peer, 25, false)
			if r.Valid || r.Error != tc.error {
				t.Fatal(r)
			}
		})
	}
	binary.BigEndian.PutUint32(good[22:26], 25)
	if r := parseEchoReply(good, nonce, source, peer, 25, false); !r.Valid || r.ScopeBE != 25 {
		t.Fatal(r)
	}
}

func TestUnreportedReplyScopeIsOnlyContentEvidence(t *testing.T) {
	b, nonce := packedEchoFixture(t)
	source, peer := net.ParseIP("fe80::1"), net.ParseIP("fe80::40b:7690:e7c4:8507")
	clear(b[22:26]) // Leave padding nonzero; it is not a scope.
	r := parseEchoReply(b, nonce, source, peer, 25, false)
	if !r.Valid || r.ScopeLE != 0 || r.ScopeBE != 0 || !r.NonceMatches {
		t.Fatal(r)
	}
	if r := parseEchoReply(b, nonce, source, peer, 0, false); r.Valid {
		t.Fatal(r)
	}
	b[36] ^= 1
	if r := parseEchoReply(b, nonce, source, peer, 25, false); r.Valid {
		t.Fatal(r)
	}
}

func TestEchoReplyRequestMustBeLinkLocalAndHaveExactNonceLength(t *testing.T) {
	b, nonce := packedEchoFixture(t)
	source, peer := net.ParseIP("fe80::1"), net.ParseIP("fe80::40b:7690:e7c4:8507")
	if r := parseEchoReply(b, nonce[:31], source, peer, 25, false); r.Valid {
		t.Fatal(r)
	}
	for _, s := range []string{"", "::1", "ff02::1", "2001:db8::1", "169.254.1.2"} {
		if r := parseEchoReply(b, nonce, net.ParseIP(s), peer, 25, false); r.Valid {
			t.Fatal(s, r)
		}
	}
	if r := parseEchoReply(b, nonce, source, net.ParseIP("ff02::1"), 25, true); !r.Valid {
		t.Fatal(r)
	}
	if r := parseEchoReply(b, nonce, source, net.ParseIP("ff02::2"), 25, true); r.Valid {
		t.Fatal(r)
	}
}
func TestPeerCandidatesCannotBeInternetMulticastIPv4OrLocal(t *testing.T) {
	source := net.ParseIP("fe80::1")
	for _, s := range []string{"", "fe80::1", "ff02::1", "::1", "2001:db8::1", "169.254.1.2"} {
		if eligibleIPv6Peer(net.ParseIP(s), source) {
			t.Fatal(s)
		}
	}
	if !eligibleIPv6Peer(net.ParseIP("fe80::2"), source) {
		t.Fatal("valid peer rejected")
	}
}
