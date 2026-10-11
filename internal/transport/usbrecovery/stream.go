// Package usbrecovery carries the existing TLS maintenance API over a bounded
// USB datagram stream. It does not expose a generic network bridge or commands.
package usbrecovery

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const Hello = "USB-LINK-RECOVERY/1 "
const Port = 47773
const Chunk = 1024
const header = 31

var magic = []byte("USBLR1")

type Conn struct {
	ctx         context.Context
	cancel      context.CancelFunc
	id          [16]byte
	send        func([]byte) error
	mu          sync.Mutex
	rx, tx, ack uint64
	input       chan []byte
	notify      chan struct{}
	readWake    chan struct{}
	rd, wd      time.Time
	rmu, wmu    sync.Mutex
	remainder   []byte
	closeOnce   sync.Once
}

func NewConn(ctx context.Context, id [16]byte, send func([]byte) error) *Conn {
	ctx, cancel := context.WithCancel(ctx)
	return &Conn{ctx: ctx, cancel: cancel, id: id, send: send, input: make(chan []byte, 32), notify: make(chan struct{}, 1), readWake: make(chan struct{}, 1)}
}
func (c *Conn) packet(kind byte, seq uint64, body []byte) []byte {
	p := make([]byte, header+len(body))
	copy(p, magic)
	copy(p[6:], c.id[:])
	p[22] = kind
	binary.BigEndian.PutUint64(p[23:], seq)
	copy(p[header:], body)
	return p
}

// Ingest is called only by the transport's one validated USB peer reader.
// Full queues are not acknowledged; duplicates/reordering cannot grow memory.
func (c *Conn) Ingest(p []byte) bool {
	if len(p) < header || len(p) > header+Chunk || !bytes.Equal(p[:6], magic) || !bytes.Equal(p[6:22], c.id[:]) {
		return false
	}
	seq := binary.BigEndian.Uint64(p[23:])
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return false
	}
	switch p[22] {
	case 1:
		if len(p) == header {
			c.mu.Unlock()
			return false
		}
		if seq == c.rx {
			select {
			case c.input <- append([]byte(nil), p[header:]...):
				c.rx++
			default:
			}
		}
		next := c.rx
		c.mu.Unlock()
		_ = c.send(c.packet(2, next, nil))
		return true
	case 3:
		if len(p) != header {
			c.mu.Unlock()
			return false
		}
		c.mu.Unlock()
		c.cancel()
		return true
	case 2:
		if len(p) != header || seq > c.tx {
			c.mu.Unlock()
			return false
		}
		if seq > c.ack {
			c.ack = seq
			select {
			case c.notify <- struct{}{}:
			default:
			}
		}
		c.mu.Unlock()
		return true
	default:
		c.mu.Unlock()
		return false
	}
}
func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.remainder) == 0 {
		c.mu.Lock()
		deadline := c.rd
		c.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(max(0, time.Until(deadline)))
			timeout = timer.C
		}
		select {
		case c.remainder = <-c.input:
		case <-c.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return 0, io.EOF
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		case <-c.readWake:
		}
		if timer != nil {
			timer.Stop()
		}
	}
	n := copy(b, c.remainder)
	c.remainder = c.remainder[n:]
	return n, nil
}
func (c *Conn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(b) > 0 {
		// A bounded sliding window avoids one RTT for every kilobyte. The receiver
		// only queues contiguous chunks and cumulatively ACKs, never buffers gaps.
		count := min(16, (len(b)+Chunk-1)/Chunk)
		c.mu.Lock()
		start := c.tx
		c.tx += uint64(count)
		target := c.tx
		c.mu.Unlock()
		packets := make([][]byte, count)
		sizes := make([]int, count)
		offset := 0
		for i := range packets {
			n := min(Chunk, len(b)-offset)
			packets[i] = c.packet(1, start+uint64(i), b[offset:offset+n])
			sizes[i] = n
			offset += n
		}
		fallback := time.Now().Add(20 * time.Second)
		last := time.Time{}
		completed := 0
		for {
			if c.ctx.Err() != nil {
				return written, io.ErrClosedPipe
			}
			c.mu.Lock()
			ack, deadline := c.ack, c.wd
			c.mu.Unlock()
			for completed < count && start+uint64(completed) < ack {
				written += sizes[completed]
				completed++
			}
			if ack == target {
				break
			}
			if deadline.IsZero() {
				deadline = fallback
			}
			if !time.Now().Before(deadline) {
				c.Close()
				return written, os.ErrDeadlineExceeded
			}
			if time.Since(last) >= 30*time.Millisecond {
				for i := completed; i < count; i++ {
					if e := c.send(packets[i]); e != nil {
						c.Close()
						return written, e
					}
				}
				last = time.Now()
			}
			t := time.NewTimer(min(30*time.Millisecond, time.Until(deadline)))
			select {
			case <-c.notify:
			case <-c.ctx.Done():
			case <-t.C:
			}
			t.Stop()
		}
		b = b[offset:]
	}
	return written, nil
}
func (c *Conn) Close() error {
	c.closeOnce.Do(func() { c.cancel(); _ = c.send(c.packet(3, 0, nil)) })
	return nil
}
func (c *Conn) Done() <-chan struct{}         { return c.ctx.Done() }
func (c *Conn) LocalAddr() net.Addr           { return &net.TCPAddr{IP: net.IPv4(10, 6, 9, 1), Port: 47775} }
func (c *Conn) RemoteAddr() net.Addr          { return &net.TCPAddr{IP: net.IPv4(10, 6, 9, 2), Port: 47775} }
func (c *Conn) SetDeadline(t time.Time) error { c.SetReadDeadline(t); return c.SetWriteDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rd = t
	c.mu.Unlock()
	select {
	case c.readWake <- struct{}{}:
	default:
	}
	return nil
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wd = t
	c.mu.Unlock()
	select {
	case c.notify <- struct{}{}:
	default:
	}
	return nil
}
