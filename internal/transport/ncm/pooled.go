package ncm

import (
	"fmt"
	"sync/atomic"
)

// BufferPool stores only Go-owned copies. A WinUSB read buffer is never retained.
type BufferPool interface {
	Get(int) []byte
	Put([]byte)
}
type blockStorage struct {
	pool      BufferPool
	bytes     []byte
	remaining atomic.Int32
}

// Release must be called once by an opting-in owner, after all borrowed frames
// have been consumed. Default Decode/Stream results remain independently owned.
func (b Block) Release() {
	if b.storage != nil && b.storage.remaining.Add(-1) == 0 {
		b.storage.pool.Put(b.storage.bytes)
	}
}
func (s *Stream) Close() {
	if s.pendingPool != nil {
		s.pendingPool.Put(s.Pending)
	}
	s.Pending = nil
	s.pendingPool = nil
}
func (s *Stream) feedPooled(b []byte) (out []Block, err error) {
	n := len(s.Pending) + len(b)
	data := s.Pending
	owner := s.pendingPool
	if cap(data) < n {
		if s.Pool != nil {
			data = s.Pool.Get(n)
			owner = s.Pool
		} else {
			data = make([]byte, n)
			owner = nil
		}
		copy(data, s.Pending)
		if s.pendingPool != nil {
			s.pendingPool.Put(s.Pending)
		}
	} else {
		data = data[:n]
	}
	copy(data[n-len(b):], b)
	s.Pending = nil
	s.pendingPool = nil
	remaining := data
	// Until successful return no block has been handed to another owner.
	defer func() {
		if err != nil && owner != nil {
			owner.Put(data)
		}
	}()
	for len(remaining) >= 12 {
		if string(remaining[:4]) != "NCMH" {
			return nil, fmt.Errorf("unexpected format/header %x", remaining[:12])
		}
		size := int(le.Uint16(remaining[8:]))
		if size < 12 {
			return nil, fmt.Errorf("invalid stream block length %d", size)
		}
		if len(remaining) < size {
			break
		}
		block, e := Decode(remaining[:size])
		if e != nil {
			return nil, e
		}
		out = append(out, block)
		remaining = remaining[size:]
	}
	if len(out) == 0 {
		s.Pending = data
		s.pendingPool = owner
		return out, nil
	}
	if len(remaining) > 0 {
		if s.Pool != nil {
			s.Pending = s.Pool.Get(len(remaining))
			s.pendingPool = s.Pool
			copy(s.Pending, remaining)
		} else {
			s.Pending = append([]byte(nil), remaining...)
		}
	}
	if owner != nil {
		storage := &blockStorage{pool: owner, bytes: data}
		storage.remaining.Store(int32(len(out)))
		for i := range out {
			out[i].storage = storage
		}
	}
	return out, nil
}
