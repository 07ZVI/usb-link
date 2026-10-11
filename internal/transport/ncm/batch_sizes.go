package ncm

import "fmt"

// Pack already-ready frames by their actual encoded size, without waiting for
// more packets. A short TCP tail must not reduce all its neighbours to the
// worst-case count for a 9000/16000-byte frame.
type BatchSizes struct {
	parameters Parameters
	requested  int
	FrameLimit int
}

func NewBatchSizes(p Parameters, requested int, maxFrame int) (BatchSizes, error) {
	b := BatchSizes{parameters: p, requested: requested}
	for i, size := range []int{1514, 9014, 16014} {
		if size > maxFrame {
			break
		}
		_, err := BatchLimit(p, size, requested)
		if err != nil {
			if i == 0 {
				return b, err
			}
			break
		}
		b.FrameLimit = size
	}
	return b, nil
}
func (b BatchSizes) Limit(frames [][]byte) (int, error) {
	if len(frames) == 0 {
		return 0, fmt.Errorf("empty batch")
	}
	for _, f := range frames {
		if len(f) < 14 || len(f) > b.FrameLimit {
			return 0, fmt.Errorf("frame exceeds verified transport capacity: %d", len(f))
		}
	}
	p := b.parameters
	maximum := min(len(frames), b.requested)
	if p.OutDatagrams != 0 {
		maximum = min(maximum, int(p.OutDatagrams))
	}
	limit := int(min(uint32(MaxNTB), p.OutMax))
	alignment, divisor, remainder := int(p.OutAlignment), int(p.OutDivisor), int(p.OutRemainder)
	ndp := (12 + alignment - 1) / alignment * alignment
	fitting := 0
	for count := 1; count <= maximum; count++ {
		cursor := ndp + 8 + 4*(count+1)
		for _, f := range frames[:count] {
			cursor += (remainder - (cursor+14)%divisor + divisor) % divisor
			cursor += len(f)
		}
		if cursor > limit {
			break
		}
		fitting = count
	}
	if fitting == 0 {
		return 0, fmt.Errorf("first frame exceeds NTB capacity")
	}
	return fitting, nil
}
