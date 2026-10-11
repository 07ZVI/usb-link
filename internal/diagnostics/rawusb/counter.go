package rawusb

import (
	"sync"
	"time"
)

type Counts struct {
	CorruptSamples     uint64    `json:"corrupt_samples"`
	Packets            uint64    `json:"packets"`
	UniquePackets      uint64    `json:"unique_packets"`
	PayloadBytes       uint64    `json:"payload_bytes"`
	UniquePayloadBytes uint64    `json:"unique_payload_bytes"`
	IPBytes            uint64    `json:"ip_bytes"`
	Duplicates         uint64    `json:"duplicates"`
	Reordered          uint64    `json:"reordered"`
	SequenceOverflow   uint64    `json:"sequence_overflow"`
	MaxSequence        [4]uint64 `json:"max_sequence"`
	FlowPackets        [4]uint64 `json:"flow_packets"`
	FirstPacketSeconds float64   `json:"first_packet_seconds"`
	LastPacketSeconds  float64   `json:"last_packet_seconds"`
	USBReads           uint64    `json:"usb_reads"`
	USBReadBytes       uint64    `json:"usb_read_bytes"`
}
type Counter struct {
	mu      sync.Mutex
	bits    [4][]uint64
	counts  Counts
	started time.Time
	stopped bool
}

func NewCounter() *Counter {
	c := &Counter{started: time.Now()}
	for i := range c.bits {
		c.bits[i] = make([]uint64, sequenceBits/64)
	}
	return c
}
func (c *Counter) Read(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.counts.USBReads++
		c.counts.USBReadBytes += uint64(n)
	}
}
func (c *Counter) Add(p []byte, nonce [16]byte) bool {
	seq, flow, ok := Identity(p, nonce)
	if !ok {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return true
	}
	v := &c.counts
	v.Packets++
	if seq%4096 == 0 {
		for i := Header; i < len(p); i++ {
			if p[i] != byte(i%251) {
				v.CorruptSamples++
				break
			}
		}
	}
	v.PayloadBytes += uint64(len(p))
	v.IPBytes += uint64(len(p) + 28)
	if v.Packets == 1 {
		v.FirstPacketSeconds = time.Since(c.started).Seconds()
	}
	v.LastPacketSeconds = time.Since(c.started).Seconds()
	if seq >= sequenceBits {
		v.SequenceOverflow++
		return true
	}
	word, mask := seq/64, uint64(1)<<(seq%64)
	if c.bits[flow][word]&mask != 0 {
		v.Duplicates++
		return true
	}
	c.bits[flow][word] |= mask
	if v.FlowPackets[flow] > 0 && seq < v.MaxSequence[flow] {
		v.Reordered++
	}
	if seq > v.MaxSequence[flow] {
		v.MaxSequence[flow] = seq
	}
	v.UniquePackets++
	v.UniquePayloadBytes += uint64(len(p))
	v.FlowPackets[flow]++
	return true
}
func (c *Counter) Stop() Counts     { c.mu.Lock(); defer c.mu.Unlock(); c.stopped = true; return c.counts }
func (c *Counter) Snapshot() Counts { c.mu.Lock(); defer c.mu.Unlock(); return c.counts }

type Receiver struct {
	Nonce   [16]byte
	MAC     [6]byte
	Counter *Counter
}

func (r *Receiver) Consume(f []byte) bool {
	p, ok := Input(f, r.Nonce, r.MAC)
	return ok && r.Counter.Add(p, r.Nonce)
}

type Result struct {
	Kind                     string  `json:"kind"`
	Nonce                    string  `json:"nonce"`
	Direction                string  `json:"direction"`
	IPLength                 int     `json:"ip_length"`
	FramesPerNTB             int     `json:"frames_per_ntb"`
	NTBLength                int     `json:"ntb_length"`
	Seconds                  float64 `json:"seconds"`
	CompletedUSBBytes        uint64  `json:"completed_usb_bytes"`
	CompletedUSBTransfers    uint64  `json:"completed_usb_transfers"`
	CompletedIPBytes         uint64  `json:"completed_ip_bytes"`
	CompletedUDPPayloadBytes uint64  `json:"completed_udp_payload_bytes"`
	SubmittedPackets         uint64  `json:"submitted_packets"`
	BeforePending            int     `json:"before_pending"`
	AfterPending             int     `json:"after_pending"`
	Counts                   Counts  `json:"received"`
	Error                    string  `json:"error,omitempty"`
}
type Capture struct {
	Raw         Result `json:"raw"`
	ProfileKind string `json:"profile_kind,omitempty"`
	Profile     []byte `json:"profile,omitempty"`
}
