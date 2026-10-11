package packetbuffer

import (
	"sync"
	"testing"
)

func TestExclusiveBuffersAndRetentionBound(t *testing.T) {
	p := New()
	var held [][]byte
	for _, size := range sizes {
		for i := 0; i < 150; i++ {
			b := p.Get(size)
			b[0] = byte(i)
			held = append(held, b)
		}
	}
	for i, b := range held {
		if b[0] != byte(i%150) {
			t.Fatal("live buffer aliased")
		}
		p.Put(b)
	}
	total := 0
	for i, q := range p.queues {
		if len(q) > depths[i] {
			t.Fatal("unbounded retention")
		}
		total += len(q) * sizes[i]
	}
	if total > RetainedLimit() {
		t.Fatal(total)
	}
	if n := testing.AllocsPerRun(100, func() { b := p.Get(16000); p.Put(b) }); n != 0 {
		t.Fatal("steady allocation", n)
	}
}
func TestConcurrentBorrowReturn(t *testing.T) {
	p := New()
	var wg sync.WaitGroup
	for id := 0; id < 8; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				b := p.Get(16000)
				for j := range b {
					b[j] = byte(id)
				}
				for _, v := range b {
					if v != byte(id) {
						t.Error("borrow alias")
						break
					}
				}
				p.Put(b)
			}
		}(id)
	}
	wg.Wait()
}
