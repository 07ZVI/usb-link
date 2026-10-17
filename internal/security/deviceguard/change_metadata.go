package deviceguard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"time"
)

const changeMetadataCapacity = 128

// The key identifies a node only within this subscription. No instance path or
// salt leaves the callback, and a notification never grants device authority.
type ChangeMetadata struct {
	Sequence  uint64 `json:"sequence"`
	UTC       string `json:"event_utc"`
	Action    string `json:"action"`
	NodeKey   string `json:"node_key"`
	Product   uint16 `json:"product_id"`
	Interface int    `json:"interface_number"`
}

type ChangeMetadataStats struct {
	Observed          uint64 `json:"observed"`
	QueueDropped      uint64 `json:"queue_dropped"`
	Rejected          uint64 `json:"rejected"`
	RejectedSize      uint64 `json:"rejected_size"`
	RejectedInstance  uint64 `json:"rejected_instance_metadata"`
	RejectedInterface uint64 `json:"rejected_interface_metadata"`
	UnregisterFailed  uint64 `json:"unregister_failed"`
}

type ChangeMetadataStream struct {
	mu     sync.Mutex
	salt   [32]byte
	closed bool
	stats  ChangeMetadataStats
	events chan ChangeMetadata
}

func newChangeMetadataStream() (*ChangeMetadataStream, error) {
	s := &ChangeMetadataStream{events: make(chan ChangeMetadata, changeMetadataCapacity)}
	if _, err := rand.Read(s.salt[:]); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ChangeMetadataStream) Events() <-chan ChangeMetadata { return s.events }
func (s *ChangeMetadataStream) Stats() ChangeMetadataStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// Closing admission is memory-only and precedes native unregistration.
func (s *ChangeMetadataStream) StopAdmission() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	clear(s.salt[:])
}

func (s *ChangeMetadataStream) unregisterFailed() {
	s.mu.Lock()
	s.stats.UnregisterFailed++
	s.mu.Unlock()
}

func (s *ChangeMetadataStream) reject(kind uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.stats.Rejected++
		switch kind {
		case 0:
			s.stats.RejectedInterface++
		case 2:
			s.stats.RejectedInstance++
		default:
			s.stats.RejectedSize++
		}
	}
}

func appleChangeIdentity(instance string) (uint16, int, bool) {
	parts := strings.Split(strings.ToUpper(instance), `\`)
	if len(parts) != 3 || parts[0] != "USB" || !strings.HasPrefix(parts[1], "VID_05AC&PID_12") || parts[2] == "" || len(instance) > 1024 {
		return 0, -1, false
	}
	id := parts[1]
	if len(id) < 17 {
		return 0, -1, false
	}
	product, err := strconv.ParseUint(id[13:17], 16, 16)
	if err != nil {
		return 0, -1, false
	}
	iface := -1
	if at := strings.Index(id, "&MI_"); at >= 0 {
		if at+6 > len(id) {
			return 0, -1, false
		}
		n, err := strconv.ParseUint(id[at+4:at+6], 16, 8)
		if err != nil {
			return 0, -1, false
		}
		iface = int(n)
	}
	return uint16(product), iface, true
}

func (s *ChangeMetadataStream) offer(action uintptr, instance string, at time.Time) {
	name := ""
	switch action {
	case 0:
		name = "usb_interface_arrival"
	case 1:
		name = "usb_interface_removal"
	case 7:
		name = "instance_enumerated"
	case 8:
		name = "instance_started"
	case 9:
		name = "instance_removed"
	}
	product, iface, valid := appleChangeIdentity(instance)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if name == "" || !valid {
		s.stats.Rejected++
		return
	}
	s.stats.Observed++
	h := hmac.New(sha256.New, s.salt[:])
	h.Write([]byte(strings.ToUpper(instance)))
	e := ChangeMetadata{Sequence: s.stats.Observed, UTC: at.UTC().Format(time.RFC3339Nano), Action: name, NodeKey: hex.EncodeToString(h.Sum(nil)[:16]), Product: product, Interface: iface}
	select {
	case s.events <- e:
	default:
		s.stats.QueueDropped++
	}
}
