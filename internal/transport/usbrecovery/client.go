package usbrecovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"suhang/usbnet/internal/transport/usbroute"
	"sync"
	"syscall"
	"time"
)

// Client binds only the DHCP-assigned USB address and fixed maintenance port.
// The invitation is authenticated by the same certificate pin and publisher
// signature checks as the normal developer client; it is never printed.
type Client struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	first   *Conn
	active  []*Conn
	sockets []*net.UDPConn
}

func Discover(ctx context.Context) ([]byte, *Client, error) {
	lifetime, cancel := context.WithCancel(context.Background())
	c := &Client{ctx: lifetime, cancel: cancel}
	b, conn, e := c.open(ctx)
	if e != nil {
		c.Close()
		return nil, nil, e
	}
	c.first = conn
	return b, c, nil
}
func (c *Client) open(ctx context.Context) ([]byte, *Conn, error) {
	peer := &net.UDPAddr{IP: net.IPv4(10, 6, 9, 1), Port: Port}
	var s *net.UDPConn
	var e error
	deadline := time.Now().Add(15 * time.Second)
	for {
		s, e = usbroute.ListenUDP(ctx, &net.UDPAddr{IP: net.IPv4(10, 6, 9, 2), Port: Port})
		if e == nil {
			break
		}
		if !errors.Is(e, syscall.EADDRNOTAVAIL) || !time.Now().Before(deadline) {
			return nil, nil, fmt.Errorf("USB recovery address unavailable: %w", e)
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		return nil, nil, e
	}
	prefix := Hello + hex.EncodeToString(id[:])
	buf := make([]byte, 2048)
	var inv []byte
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	for attempt := 0; attempt < 20 && ctx.Err() == nil; attempt++ {
		s.SetWriteDeadline(time.Now().Add(time.Second))
		if _, e = s.WriteToUDP([]byte(prefix), peer); e != nil {
			return nil, nil, e
		}
		s.SetReadDeadline(time.Now().Add(time.Second))
		for {
			n, from, err := s.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if from.Port != Port || !from.IP.Equal(peer.IP) || n <= len(prefix)+1 || n > 1400 || string(buf[:len(prefix)+1]) != prefix+" " {
				continue
			}
			candidate := buf[len(prefix)+1 : n]
			var marker struct {
				Transport string `json:"transport"`
			}
			if json.Unmarshal(candidate, &marker) != nil || marker.Transport != "usb-recovery" {
				continue
			}
			inv = append([]byte(nil), candidate...)
			break
		}
		if inv != nil {
			break
		}
	}
	if inv == nil {
		return nil, nil, fmt.Errorf("USB recovery not responding; keep USB connected and developer debugging enabled")
	}
	s.SetDeadline(time.Time{})
	conn := NewConn(c.ctx, id, func(p []byte) error { _, e := s.WriteToUDP(p, peer); return e })
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		conn.Close()
		return nil, nil, c.ctx.Err()
	}
	c.active = []*Conn{conn}
	c.sockets = []*net.UDPConn{s}
	c.mu.Unlock()
	go func() {
		defer conn.Close()
		defer s.Close()
		for {
			n, from, e := s.ReadFromUDP(buf)
			if e != nil {
				return
			}
			if from.Port == Port && from.IP.Equal(peer.IP) {
				conn.Ingest(buf[:n])
			}
		}
	}()
	go func() { <-conn.Done(); s.Close() }()
	ok = true
	return inv, conn, nil
}
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" || address != "10.6.9.1:47775" {
		return nil, fmt.Errorf("USB maintenance destination required")
	}
	c.mu.Lock()
	first := c.first
	c.first = nil
	c.mu.Unlock()
	if first != nil {
		return first, nil
	}
	c.mu.Lock()
	for i, old := range c.active {
		select {
		case <-old.Done():
			c.sockets[i].Close()
		default:
			c.mu.Unlock()
			return nil, fmt.Errorf("USB recovery session already active")
		}
	}
	c.mu.Unlock()
	_, conn, e := c.open(ctx)
	return conn, e
}
func (c *Client) Close() {
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, conn := range c.active {
		conn.Close()
	}
	for _, s := range c.sockets {
		s.Close()
	}
}
