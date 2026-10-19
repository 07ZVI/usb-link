package bridge

import "sync/atomic"

// DropReason names why FromMacReason produced neither an ARP reply nor an IPv4
// packet, or why the Wintun owner discarded an accepted packet.
type DropReason uint8

const (
	DropNone DropReason = iota
	DropEthernet
	DropEtherType // not ARP/IPv4, for example IPv6 neighbour or mDNS traffic
	DropDestinationMAC
	DropIPv4Invalid // malformed header, length or checksum
	DropOversize    // IPv4 total length above the published peer MTU
	DropIPAddress   // source/destination outside the USB peer addresses
	DropPeerMAC     // sender MAC is invalid or differs from the learned peer
	DropARPMalformed
	DropARPAddress
	DropDHCPSource // Unified profile: source differs from the DHCP-fixed MAC
	DropRingFull   // Wintun session ring had no room
	dropReasons
)

var dropReasonNames = [dropReasons]string{"none", "ethernet", "ethertype", "dest_mac", "ipv4_invalid", "oversize", "ip_address", "peer_mac", "arp_malformed", "arp_address", "dhcp_source", "wintun_ring_full"}

func (r DropReason) String() string {
	if r < dropReasons {
		return dropReasonNames[r]
	}
	return "unknown"
}

// DropCounts has a single owning goroutine; Named returns a copy keyed by reason.
type DropCounts [dropReasons]uint64

func (d *DropCounts) Add(r DropReason) { d[r]++ }
func (d *DropCounts) Named() map[string]uint64 {
	out := map[string]uint64{}
	for r := DropReason(1); r < dropReasons; r++ {
		if d[r] != 0 {
			out[r.String()] = d[r]
		}
	}
	return out
}

// IngressCounters describes the USB IN to Wintun path. They are updated once per
// USB transfer or NTB (never per packet) with atomics so the statistics owner can
// read them without a lock.
type IngressCounters struct {
	Submitted, Completed, Bytes     atomic.Uint64
	ReadyImmediately, WaitedForIO   atomic.Uint64 // completion already present vs had to wait
	Blocks, Datagrams, DecodeErrors atomic.Uint64
	ShortReads, FullReads           atomic.Uint64 // length below half / at the submitted buffer size
	MaxRead                         atomic.Uint64
	WaitNanos, FeedNanos            atomic.Uint64 // blocked for completion; NTB feed/parse
	HandoffNanos                    atomic.Uint64 // blocked handing blocks to the Wintun owner
	QueueFullEvents                 atomic.Uint64 // hand-off found the queue already full
	ProcessNanos, ProcessedBlocks   atomic.Uint64 // Wintun owner: time spent per block
	MaxQueue                        atomic.Uint64
}

type IngressSnapshot struct {
	Submitted, Completed, Outstanding, Bytes uint64
	ReadyImmediately, WaitedForIO            uint64
	Blocks, Datagrams, DecodeErrors          uint64
	ShortReads, FullReads, MaxRead           uint64
	WaitNanos, FeedNanos, HandoffNanos       uint64
	QueueFullEvents, MaxQueue                uint64
	ProcessNanos, ProcessedBlocks            uint64
}

func (c *IngressCounters) Snapshot() IngressSnapshot {
	s := IngressSnapshot{Submitted: c.Submitted.Load(), Completed: c.Completed.Load(), Bytes: c.Bytes.Load(),
		ReadyImmediately: c.ReadyImmediately.Load(), WaitedForIO: c.WaitedForIO.Load(),
		Blocks: c.Blocks.Load(), Datagrams: c.Datagrams.Load(), DecodeErrors: c.DecodeErrors.Load(),
		ShortReads: c.ShortReads.Load(), FullReads: c.FullReads.Load(), MaxRead: c.MaxRead.Load(),
		WaitNanos: c.WaitNanos.Load(), FeedNanos: c.FeedNanos.Load(), HandoffNanos: c.HandoffNanos.Load(),
		QueueFullEvents: c.QueueFullEvents.Load(), MaxQueue: c.MaxQueue.Load(),
		ProcessNanos: c.ProcessNanos.Load(), ProcessedBlocks: c.ProcessedBlocks.Load()}
	if s.Submitted >= s.Completed {
		s.Outstanding = s.Submitted - s.Completed
	}
	return s
}

// ObserveRead records one completed IN transfer of n bytes into a size-byte buffer.
// Only the USB IN goroutine calls it.
func (c *IngressCounters) ObserveRead(n, size int, immediate bool) {
	c.Completed.Add(1)
	c.Bytes.Add(uint64(n))
	if immediate {
		c.ReadyImmediately.Add(1)
	} else {
		c.WaitedForIO.Add(1)
	}
	if n >= size {
		c.FullReads.Add(1)
	} else if n < size/2 {
		c.ShortReads.Add(1)
	}
	if uint64(n) > c.MaxRead.Load() {
		c.MaxRead.Store(uint64(n))
	}
}

// ObserveQueue is called by the single USB IN goroutine.
func (c *IngressCounters) ObserveQueue(depth int) {
	if uint64(depth) > c.MaxQueue.Load() {
		c.MaxQueue.Store(uint64(depth))
	}
}
