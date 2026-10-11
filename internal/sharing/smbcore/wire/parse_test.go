package wire

import (
	"encoding/binary"
	"testing"
)

// Client-controlled lengths must fail without a panic or an unbounded allocation.
func FuzzRequestParsers(f *testing.F) {
	for _, size := range []int{0, 4, 64, 88, 104, 4096} {
		f.Add(make([]byte, size))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 16384 {
			return
		}
		var h Header
		h.Parse(b)
		var a CreateRequest
		a.Parse(b)
		var r ReadRequest
		r.Parse(b)
		var w WriteRequest
		w.Parse(b)
		var q QueryInfoRequest
		q.Parse(b)
		var d QueryDirectoryRequest
		d.Parse(b)
		var s SetInfoRequest
		s.Parse(b)
		var i IoctlRequest
		i.Parse(b)
		var l LockRequest
		l.Parse(b)
		var n NegotiateRequest
		n.Parse(b)
	})
}

func TestMinimalNativeQueriesAndLockCountBounds(t *testing.T) {
	msg := make([]byte, 104)
	binary.LittleEndian.PutUint16(msg[64:], 41)
	var q QueryInfoRequest
	if err := q.Parse(msg); err != nil {
		t.Fatal("valid native query rejected", err)
	}
	lock := make([]byte, 112)
	binary.LittleEndian.PutUint16(lock[64:], 48)
	binary.LittleEndian.PutUint16(lock[66:], 1)
	var l LockRequest
	if err := l.Parse(lock); err != nil || len(l.Locks) != 1 {
		t.Fatal("valid lock", err)
	}
	binary.LittleEndian.PutUint16(lock[66:], 65535)
	if err := l.Parse(lock); err == nil {
		t.Fatal("unbounded lock array accepted")
	}
}
