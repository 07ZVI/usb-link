// Package packetbuffer keeps a fixed upper bound on retained transfer buffers.
// A caller owns a Get result exclusively until exactly one Put after consumption.
package packetbuffer

type Pool struct {
	queues  [5]chan []byte
	Enabled func() bool
}

var sizes = [5]int{2048, 16384, 32768, 65536, 131072}
var depths = [5]int{64, 128, 64, 16, 4}

func New() *Pool {
	p := new(Pool)
	for i, n := range depths {
		p.queues[i] = make(chan []byte, n)
	}
	return p
}
func (p *Pool) Get(n int) []byte {
	for i, size := range sizes {
		if n <= size {
			select {
			case b := <-p.queues[i]:
				return b[:n]
			default:
				return make([]byte, n, size)
			}
		}
	}
	return make([]byte, n)
}
func (p *Pool) Put(b []byte) {
	if p.Enabled != nil && !p.Enabled() {
		return
	}
	for i, size := range sizes {
		if cap(b) == size {
			select {
			case p.queues[i] <- b[:0]:
			default:
			}
			return
		}
	}
}

// RetainedLimit includes bytes only, and is independent of traffic volume.
func RetainedLimit() int {
	n := 0
	for i, size := range sizes {
		n += size * depths[i]
	}
	return n
}

func (p *Pool) Trim() {
	for _, q := range p.queues {
		for {
			select {
			case <-q:
			default:
				goto drained
			}
		}
	drained:
	}
}
