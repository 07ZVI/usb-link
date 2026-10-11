// Package mtutrial verifies a jumbo frame round trip without asking the peer
// to install software. Only bounded nonce-matching, unfragmented ICMP replies
// from the already authorized USB Ethernet identity count as proof.
package mtutrial

import (
	"bytes"
	"encoding/binary"
	"suhang/usbnet/internal/transport/bridge"
	"suhang/usbnet/internal/transport/ncm"
	"time"
)

type Trial struct {
	Nonce                    [16]byte
	MAC                      [6]byte
	candidates               []int
	stage, attempts, replies int
	sequence                 uint16
	outstanding              map[uint16][]byte
	next                     time.Time
	Proven                   int
	Done                     bool
}

func New(mac [6]byte, nonce [16]byte, frameLimit int) *Trial {
	t := &Trial{MAC: mac, Nonce: nonce, Proven: 1500, outstanding: map[uint16][]byte{}}
	for _, m := range []int{9000, 16000} {
		if m+14 <= frameLimit {
			t.candidates = append(t.candidates, m)
		}
	}
	t.Done = len(t.candidates) == 0
	return t
}
func (t *Trial) advance() {
	t.stage++
	t.attempts = 0
	t.replies = 0
	clear(t.outstanding)
	t.next = time.Time{}
	t.Done = t.stage == len(t.candidates)
}

// At most four requests per size, never a timer to batch application packets.
func (t *Trial) Tick(now time.Time) []byte {
	if t.Done || now.Before(t.next) {
		return nil
	}
	if t.attempts == 4 {
		t.advance()
		if t.Done {
			return nil
		}
	}
	t.sequence++
	t.attempts++
	t.next = now.Add(time.Second)
	mtu := t.candidates[t.stage]
	ip := make([]byte, mtu)
	ip[0] = 0x45
	ip[8] = 64
	ip[9] = 1
	binary.BigEndian.PutUint16(ip[2:], uint16(mtu))
	binary.BigEndian.PutUint16(ip[6:], 0x4000)
	copy(ip[12:], ncm.WindowsIP[:])
	copy(ip[16:], ncm.MacIP[:])
	binary.BigEndian.PutUint16(ip[10:], ncm.Checksum(ip[:20]))
	icmp := ip[20:]
	icmp[0] = 8
	copy(icmp[4:6], t.Nonce[:2])
	binary.BigEndian.PutUint16(icmp[6:], t.sequence)
	copy(icmp[8:], t.Nonce[:])
	for i := 24; i < len(icmp); i++ {
		icmp[i] = byte(i) ^ t.Nonce[i%16]
	}
	binary.BigEndian.PutUint16(icmp[2:], ncm.Checksum(icmp))
	t.outstanding[t.sequence] = append([]byte(nil), icmp[8:]...)
	return ncm.Frame(t.MAC, ncm.ProbeMAC, 0x800, ip)
}

// Accept does not learn an identity, consume unrelated traffic, or count an
// ICMP error/fragment as success. Two independent requests must be returned.
func (t *Trial) Accept(frame []byte) (proven int, consumed bool) {
	if t.Done {
		return 0, false
	}
	e, err := ncm.ParseEthernet(frame)
	if err != nil || e.Type != 0x800 || e.Source != t.MAC || e.Destination != ncm.ProbeMAC {
		return
	}
	ip, err := bridge.IPv4(e.Payload, t.candidates[t.stage])
	if err != nil || len(ip) != t.candidates[t.stage] || len(ip) < 28 || ip[9] != 1 || binary.BigEndian.Uint16(ip[6:])&0x3fff != 0 || !bytes.Equal(ip[12:16], ncm.MacIP[:]) || !bytes.Equal(ip[16:20], ncm.WindowsIP[:]) {
		return
	}
	h := int(ip[0]&15) * 4
	if h+8 > len(ip) {
		return
	}
	c := ip[h:]
	if c[0] != 0 || c[1] != 0 || ncm.Checksum(c) != 0 || !bytes.Equal(c[4:6], t.Nonce[:2]) {
		return
	}
	seq := binary.BigEndian.Uint16(c[6:])
	want, ok := t.outstanding[seq]
	if !ok || !bytes.Equal(c[8:], want) {
		return
	}
	delete(t.outstanding, seq)
	t.replies++
	consumed = true
	if t.replies == 2 {
		t.Proven = t.candidates[t.stage]
		proven = t.Proven
		t.advance()
	}
	return
}
