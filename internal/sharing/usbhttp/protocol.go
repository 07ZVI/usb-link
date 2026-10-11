package usbhttp

import (
	"bufio"
	"context"
	"net"
	"sync"
	"time"
)

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type protocolListener struct {
	net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	once     sync.Once
	http     chan net.Conn
	classify chan struct{}
	binary   chan struct{}
}

func newProtocolListener(ln net.Listener, serve func(net.Conn)) *protocolListener {
	ctx, cancel := context.WithCancel(context.Background())
	l := &protocolListener{Listener: ln, ctx: ctx, cancel: cancel, http: make(chan net.Conn), classify: make(chan struct{}, 16), binary: make(chan struct{}, 4)}
	go func() {
		defer l.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case l.classify <- struct{}{}:
			default:
				conn.Close()
				continue
			}
			go func() {
				defer func() { <-l.classify }()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				r := bufio.NewReaderSize(conn, 16)
				prefix, err := r.Peek(4)
				if err != nil {
					conn.Close()
					return
				}
				conn.SetReadDeadline(time.Time{})
				buffered := &bufferedConn{Conn: conn, r: r}
				if prefix[0] == 0 {
					select {
					case l.binary <- struct{}{}:
					default:
						conn.Close()
						return
					}
					// Classification is short lived; the four binary sessions have
					// their own cap and must not starve HTTP maintenance requests.
					go func() { defer func() { <-l.binary }(); serve(buffered) }()
					return
				}
				select {
				case l.http <- buffered:
				case <-ctx.Done():
					conn.Close()
				}
			}()
		}
	}()
	return l
}
func (l *protocolListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.http:
		return conn, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (l *protocolListener) Close() error {
	var err error
	l.once.Do(func() { l.cancel(); err = l.Listener.Close() })
	return err
}
