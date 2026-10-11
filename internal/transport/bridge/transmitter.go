package bridge

import (
	"bytes"
	"context"
	"fmt"
	"suhang/usbnet/internal/transport/ncm"
	"time"
)

// TXCounters are owned by the transmitter, independently of ingress counters.
type TXCounters struct {
	Packets, Bytes, Filtered, PendingOverflow uint64
	Profile                                   PacketProfile
	MTUExceeded, MTUExceededBytes             uint64
	MaxRejectedIPLength                       uint32
}

// Transmitter owns the USB OUT writer and all outbound packet ordering. Peer
// returns an immutable snapshot published by ingress after identity validation.
// Neither Write nor Poll may be called concurrently outside this owner.
type Transmitter struct {
	// Bounded diagnostic work runs exclusively on the existing OUT owner.
	Work      <-chan func() error
	Packets   <-chan []byte
	Controls  <-chan [][]byte
	PeerReady <-chan struct{}
	Peer      func() Peer
	Batch     int
	Write     func([][]byte) error
	Poll      func() error
	Pending   func() bool
	Changed   func(TXCounters)
	// ReuseFrames requires Write to finish consuming/copying frame bytes before
	// returning. Only the owned WinUSB writer opts in; legacy callers keep owned
	// frame results. Packet/control bytes are never reused or modified here.
	ReuseFrames bool
	// Optional benchmark switch is sampled by the sole OUT owner.
	ReuseFramesNow func() bool
	// Opt-in ownership: release exactly once after copying/consumption, including
	// invalid packets, pending overflow and cancellation.
	ReleasePacket func([]byte)
}

func (t Transmitter) Run(ctx context.Context) error {
	if t.Peer == nil || t.Write == nil || t.Poll == nil || t.Batch < 1 || t.Batch > 512 {
		return fmt.Errorf("invalid transmitter")
	}
	var stats TXCounters
	publish := func() {
		if t.Changed != nil {
			t.Changed(stats)
		}
	}
	defer publish()
	var frameSlots, packetSlots, frameHeaders [][]byte
	if t.ReuseFrames || t.ReuseFramesNow != nil {
		frameSlots = make([][]byte, t.Batch)
		packetSlots = make([][]byte, 0, t.Batch)
		frameHeaders = make([][]byte, 0, t.Batch)
	}
	wasReuse := false
	sendPackets := func(packets [][]byte) error {
		if t.ReleasePacket != nil {
			defer func() {
				for _, p := range packets {
					t.ReleasePacket(p)
				}
			}()
		}
		reuse := t.ReuseFrames
		if t.ReuseFramesNow != nil {
			reuse = t.ReuseFramesNow()
		}
		if !reuse && wasReuse {
			clear(frameSlots)
			clear(frameHeaders[:cap(frameHeaders)])
		}
		wasReuse = reuse
		p := t.Peer()
		var frames [][]byte
		if reuse {
			frames = frameHeaders[:0]
		} else {
			frames = make([][]byte, 0, t.Batch)
		}
		for _, packet := range packets {
			var frame []byte
			var e error
			if reuse {
				frame, e = p.FromWindowsInto(packet, frameSlots[len(frames)])
			} else {
				frame, e = p.FromWindows(packet)
			}
			if e != nil {
				stats.Filtered++
				// Separate valid, exact-peer oversize packets from unrelated or
				// corrupt traffic. Accepted packets keep their existing hot path.
				if len(packet) > p.MTU {
					if ip, err := IPv4(packet, 65535); err == nil && len(ip) > p.MTU && bytes.Equal(ip[12:16], ncm.WindowsIP[:]) && bytes.Equal(ip[16:20], ncm.MacIP[:]) {
						stats.MTUExceeded++
						stats.MTUExceededBytes += uint64(len(ip))
						stats.MaxRejectedIPLength = max(stats.MaxRejectedIPLength, uint32(len(ip)))
					}
				}
				continue
			}
			if reuse {
				frameSlots[len(frames)] = frame
			}
			frames = append(frames, frame)
			stats.Packets++
			stats.Bytes += uint64(len(packet))
			stats.Profile.Observe(packet)
			if len(frames) == t.Batch {
				if e := t.Write(frames); e != nil {
					return e
				}
				frames = frames[:0]
			}
		}
		if len(frames) > 0 {
			return t.Write(frames)
		}
		return nil
	}
	var pending [][]byte
	defer func() {
		if t.ReleasePacket != nil {
			for _, p := range pending {
				t.ReleasePacket(p)
			}
		}
	}()
	flush := func() error { e := sendPackets(pending); pending = nil; return e }
	ready := t.PeerReady
	// Completion collection only: never delays packet batching or transmission.
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	var polling <-chan time.Time
	armPolling := func() {
		if t.Pending != nil && !t.Pending() {
			if polling != nil {
				timer.Stop()
				select {
				case <-timer.C:
				default:
				}
			}
			polling = nil
			return
		}
		if polling == nil {
			timer.Reset(100 * time.Millisecond)
			polling = timer.C
		}
	}
	for {
		armPolling()
		if e := ctx.Err(); e != nil {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ready:
			ready = nil
			if e := flush(); e != nil {
				return e
			}
			publish()
		case work, ok := <-t.Work:
			if !ok {
				t.Work = nil
				continue
			}
			if e := work(); e != nil {
				return e
			}
			publish()
		case frames, ok := <-t.Controls:
			if !ok {
				t.Controls = nil
				continue
			}
			if e := t.Write(frames); e != nil {
				return e
			}
			publish()
		case packet, ok := <-t.Packets:
			if !ok {
				t.Packets = nil
				continue
			}
			p := t.Peer()
			if p.MAC == [6]byte{} {
				if _, e := IPv4(packet, p.MTU); e != nil {
					stats.Filtered++
					if t.ReleasePacket != nil {
						t.ReleasePacket(packet)
					}
				} else if len(pending) >= 64 {
					stats.PendingOverflow++
					if t.ReleasePacket != nil {
						t.ReleasePacket(packet)
					}
				} else {
					pending = append(pending, packet)
				}
				publish()
				continue
			}
			// Resolve a ready-signal/packet race without overtaking queued packets.
			if len(pending) > 0 {
				if e := flush(); e != nil {
					return e
				}
			}
			reuseBatch := t.ReuseFrames
			if t.ReuseFramesNow != nil {
				reuseBatch = t.ReuseFramesNow()
			}
			var batch [][]byte
			if reuseBatch {
				batch = ncm.ReadyBatchInto(packetSlots, packet, t.Packets, t.Batch)
			} else {
				batch = ncm.ReadyBatch(packet, t.Packets, t.Batch)
			}
			e := sendPackets(batch)
			if reuseBatch {
				clear(batch)
			}
			if e != nil {
				return e
			}
			publish()
		case <-polling:
			polling = nil
			if e := t.Poll(); e != nil {
				return e
			}
			publish()
		}
	}
}

// The fixed-capacity control queue is used only for owned ARP/DHCP/diagnostic
// frames. Cancellation releases a sender even if the OUT worker is blocked.
func EnqueueControl(ctx context.Context, queue chan<- [][]byte, frames [][]byte) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case queue <- frames:
		return nil
	}
}
