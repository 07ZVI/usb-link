// Package latencyprobe implements dormant, nonce-authenticated USB diagnostics.
package latencyprobe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"suhang/usbnet/internal/transport/bridge"
	"suhang/usbnet/internal/transport/ncm"
	"sync"
	"sync/atomic"
	"time"
)

const Limit = 12000
const Protocol = "SUHANG-USB-LATENCY/1"

type Stamp struct {
	Sequence        uint64 `json:"sequence"`
	USBReceived     int64  `json:"usb_receive_ns,omitempty"`
	WindowsInjected int64  `json:"wintun_injected_ns,omitempty"`
	WindowsReceived int64  `json:"wintun_received_ns,omitempty"`
	USBSubmitted    int64  `json:"usb_submit_ns,omitempty"`
	USBCollected    int64  `json:"usb_completion_collected_ns,omitempty"`
	USBObserved     int64  `json:"usb_completion_event_observed_ns,omitempty"`
	seen            bool
}
type Session struct {
	sync.Mutex
	ID, Mode    string
	key, nonce  []byte
	started     time.Time
	deadline    time.Time
	rows        []Stamp
	tokens      float64
	last        time.Time
	stopContext func() bool
	expiry      *time.Timer
}

var active atomic.Pointer[Session]
var sessionMu sync.Mutex

func Validate(kind string, seconds int, id, key string) error {
	n, e := hex.DecodeString(id)
	if e != nil || len(n) != 16 || hex.EncodeToString(n) != id {
		return fmt.Errorf("invalid latency nonce")
	}
	switch kind {
	case "BRIDGE", "APPLICATION", "ICMP":
		k, e := hex.DecodeString(key)
		if e != nil || len(k) != 32 || hex.EncodeToString(k) != key || seconds < 1 || seconds > 120 {
			return fmt.Errorf("invalid bounded latency start")
		}
	case "RESULT", "STOP":
		if seconds != 0 || key != "-" {
			return fmt.Errorf("invalid latency command")
		}
	default:
		return fmt.Errorf("unknown latency mode")
	}
	return nil
}
func Start(ctx context.Context, kind string, seconds int, id, key string) error {
	if e := Validate(kind, seconds, id, key); e != nil {
		return e
	}
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if active.Load() != nil {
		return fmt.Errorf("latency session already active")
	}
	k, _ := hex.DecodeString(key)
	n, _ := hex.DecodeString(id)
	now := time.Now()
	s := &Session{ID: id, Mode: kind, key: k, nonce: n, started: now, deadline: now.Add(time.Duration(seconds) * time.Second), rows: make([]Stamp, Limit), tokens: 32, last: now}
	active.Store(s)
	s.stopContext = context.AfterFunc(ctx, func() { Stop(id) })
	// Expiry preserves results briefly but disables every packet hook.
	s.expiry = time.AfterFunc(time.Duration(seconds+30)*time.Second, func() { Stop(id) })
	return nil
}
func Stop(id string) error {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	s := active.Load()
	if s != nil && s.ID != id {
		return fmt.Errorf("latency id differs")
	}
	if s != nil {
		active.CompareAndSwap(s, nil)
		if s.stopContext != nil {
			s.stopContext()
		}
		if s.expiry != nil {
			s.expiry.Stop()
		}
	}
	return nil
}
func Running() bool { s := active.Load(); return s != nil && time.Now().Before(s.deadline) }
func (s *Session) payload(ip []byte, in bool) ([]byte, bool) {
	p, e := bridge.IPv4(ip, 65535)
	if e != nil || len(p) != len(ip) || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
		return nil, false
	}
	a, b := ncm.MacIP, ncm.WindowsIP
	if !in {
		a, b = b, a
	}
	if !hmac.Equal(p[12:16], a[:]) || !hmac.Equal(p[16:20], b[:]) {
		return nil, false
	}
	h := int(p[0]&15) * 4
	if s.Mode == "ICMP" {
		if p[9] != 1 || len(p) != h+8+64 || p[h+1] != 0 || ncm.Checksum(p[h:]) != 0 {
			return nil, false
		}
		t := byte(0)
		if in {
			t = 8
		}
		if p[h] != t {
			return nil, false
		}
		return p[h+8:], true
	}
	if p[9] != 17 || len(p) != h+8+64 || binary.BigEndian.Uint16(p[h+4:]) != 72 {
		return nil, false
	}
	port := h + 2
	if !in {
		port = h
	}
	if binary.BigEndian.Uint16(p[port:]) != 10691 {
		return nil, false
	}
	if binary.BigEndian.Uint16(p[h+6:]) != 0 {
		pseudo := make([]byte, 12+len(p)-h)
		copy(pseudo, p[12:20])
		pseudo[9] = 17
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(p)-h))
		copy(pseudo[12:], p[h:])
		if ncm.Checksum(pseudo) != 0 {
			return nil, false
		}
	}
	return p[h+8:], true
}
func (s *Session) identity(ip []byte, in bool) (uint64, bool) {
	b, ok := s.payload(ip, in)
	if !ok || string(b[:8]) != "USBLRTT1" || !hmac.Equal(b[8:24], s.nonce) {
		return 0, false
	}
	seq := binary.BigEndian.Uint64(b[24:32])
	if seq >= Limit {
		return 0, false
	}
	m := hmac.New(sha256.New, s.key)
	m.Write(b[:48])
	return seq, hmac.Equal(b[48:], m.Sum(nil)[:16])
}
func Mark(ip []byte, in bool, phase string, at time.Time) {
	s := active.Load()
	if s == nil || !at.Before(s.deadline) {
		return
	}
	seq, ok := s.identity(ip, in)
	if !ok {
		return
	}
	s.Lock()
	defer s.Unlock()
	r := &s.rows[seq]
	r.Sequence = seq
	n := at.Sub(s.started).Nanoseconds()
	switch phase {
	case "usb":
		if r.USBReceived == 0 {
			r.USBReceived = n
		}
	case "inject":
		r.WindowsInjected = n
	case "receive":
		r.WindowsReceived = n
	case "submit":
		r.USBSubmitted = n
	case "complete":
		r.USBCollected = n
	}
}
func MarkFrames(frames [][]byte, peer bridge.Peer, in bool, phase string, at time.Time) {
	s := active.Load()
	if s == nil || !at.Before(s.deadline) {
		return
	}
	for _, f := range frames {
		e, err := ncm.ParseEthernet(f)
		if err != nil || e.Type != 0x800 {
			continue
		}
		if in && (e.Source != peer.MAC || e.Destination != ncm.ProbeMAC) {
			continue
		}
		Mark(e.Payload, in, phase, at)
	}
}

// Capture identities before pinned buffers can be reused. The callback retains
// no USB storage and cannot stamp a different or expired diagnostic session.
func CompletionMarker(frames [][]byte, peer bridge.Peer) func(time.Time) {
	s := active.Load()
	if s == nil || !time.Now().Before(s.deadline) {
		return nil
	}
	var sequences []uint64
	for _, f := range frames {
		e, err := ncm.ParseEthernet(f)
		if err != nil || e.Type != 0x800 {
			continue
		}
		if seq, ok := s.identity(e.Payload, false); ok {
			sequences = append(sequences, seq)
		}
	}
	if len(sequences) == 0 {
		return nil
	}
	return func(at time.Time) {
		if active.Load() != s || !at.Before(s.deadline) {
			return
		}
		s.Lock()
		defer s.Unlock()
		for _, seq := range sequences {
			s.rows[seq].Sequence = seq
			s.rows[seq].USBObserved = at.Sub(s.started).Nanoseconds()
		}
	}
}

// Receive runs only after the ordinary bridge peer/IP admission checks.
func Receive(ip []byte) (reply []byte, consumed bool) {
	s := active.Load()
	if s == nil || !time.Now().Before(s.deadline) || s.Mode != "BRIDGE" {
		return nil, false
	}
	seq, ok := s.identity(ip, true)
	if !ok {
		return nil, false
	}
	s.Lock()
	defer s.Unlock()
	r := &s.rows[seq]
	if r.seen {
		return nil, true
	}
	now := time.Now()
	s.tokens = math.Min(32, s.tokens+now.Sub(s.last).Seconds()*100)
	s.last = now
	if s.tokens < 1 {
		return nil, true
	}
	s.tokens--
	r.seen = true
	p := append([]byte(nil), ip...)
	copy(p[12:16], ip[16:20])
	copy(p[16:20], ip[12:16])
	h := int(p[0]&15) * 4
	p[h], p[h+1], p[h+2], p[h+3] = ip[h+2], ip[h+3], ip[h], ip[h+1]
	p[h+6], p[h+7] = 0, 0
	p[10], p[11] = 0, 0
	binary.BigEndian.PutUint16(p[10:], ncm.Checksum(p[:h]))
	return p, true
}
func Result(id string) (any, error) {
	s := active.Load()
	if s == nil || s.ID != id {
		return nil, fmt.Errorf("latency session unavailable")
	}
	s.Lock()
	defer s.Unlock()
	rows := []Stamp{}
	for _, r := range s.rows {
		if r.USBReceived != 0 || r.WindowsReceived != 0 {
			rows = append(rows, r)
		}
	}
	return map[string]any{"id": s.ID, "mode": s.Mode, "seconds": time.Since(s.started).Seconds(), "stamps": rows, "completion_boundary": "event_observed is a dedicated diagnostic waiter wake plus successful GetOverlappedResult; includes waiter scheduling, not physical bus time. collected remains owner collection time", "clock": "Windows process monotonic elapsed ns; never subtract Mac wall time"}, nil
}
