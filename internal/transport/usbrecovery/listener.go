package usbrecovery

import (
	"io"
	"net"
	"sync"
)

// SingleListener lets net/http retain its TLS, authentication, size limits and
// timeout behavior without creating any operating-system network listener.
type SingleListener struct {
	Conn  net.Conn
	mu    sync.Mutex
	taken bool
	done  chan struct{}
	once  sync.Once
}

func NewListener(c net.Conn) *SingleListener {
	return &SingleListener{Conn: c, done: make(chan struct{})}
}
func (l *SingleListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	first := !l.taken
	l.taken = true
	l.mu.Unlock()
	if first {
		return l.Conn, nil
	}
	<-l.done
	return nil, io.EOF
}
func (l *SingleListener) Close() error {
	l.once.Do(func() { close(l.done); l.Conn.Close() })
	return nil
}
func (l *SingleListener) Addr() net.Addr { return l.Conn.LocalAddr() }
