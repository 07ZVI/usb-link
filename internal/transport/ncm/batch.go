package ncm

import "fmt"

// BatchLimit fits worst-case Ethernet frames without exceeding the device's
// advertised NTB size/datagram count. This does not introduce a flush timer.
func BatchLimit(p Parameters, maxFrame, requested int) (int, error) {
	if maxFrame < 14 || requested < 1 || requested > 512 {
		return 0, fmt.Errorf("invalid batching limits")
	}
	frames := make([][]byte, 0, requested)
	frame := make([]byte, maxFrame)
	for count := 1; count <= requested; count++ {
		frames = append(frames, frame)
		if _, err := Encode(frames, 0, p); err != nil {
			if count == 1 {
				return 0, err
			}
			return count - 1, nil
		}
	}
	return requested, nil
}

// ReadyBatch drains only packets already available. A single packet is sent
// immediately, and a bounded drain keeps USB ingress/control work responsive.
func ReadyBatch(first []byte, ready <-chan []byte, limit int) [][]byte {
	return ReadyBatchInto(nil, first, ready, limit)
}

// ReadyBatchInto borrows a caller-owned slice header array, without borrowing
// packet bytes. As with ReadyBatch, it never waits to fill a batch.
func ReadyBatchInto(storage [][]byte, first []byte, ready <-chan []byte, limit int) [][]byte {
	packets := append(storage[:0], first)
	for len(packets) < limit {
		select {
		case packet, ok := <-ready:
			if !ok {
				return packets
			}
			packets = append(packets, packet)
		default:
			return packets
		}
	}
	return packets
}
