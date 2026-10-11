package throughput

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sync"
	"time"
)

var udpEchoState struct {
	sync.Mutex
	conn *net.UDPConn
}

// Explicitly started only via authenticated maintenance; dormant by default.
// The socket owns only .1:10691 and echoes only nonce-authenticated Mac .2.
func StartUDPEcho(ctx context.Context, key, nonce []byte, guard func() bool) error {
	if len(key) != 32 || len(nonce) != 16 || guard == nil || !guard() {
		return fmt.Errorf("authorized UDP measurement session required")
	}
	udpEchoState.Lock()
	defer udpEchoState.Unlock()
	if udpEchoState.conn != nil {
		udpEchoState.conn.Close()
	}
	conn, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.6.9.1"), Port: 10691})
	if e != nil {
		return e
	}
	udpEchoState.conn = conn
	k := append([]byte(nil), key...)
	n := append([]byte(nil), nonce...)
	go func() {
		defer conn.Close()
		defer func() {
			udpEchoState.Lock()
			if udpEchoState.conn == conn {
				udpEchoState.conn = nil
			}
			udpEchoState.Unlock()
		}()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		buf := make([]byte, 65536)
		seen := make([]bool, 12000)
		tokens := 32.0
		last := time.Now()
		for {
			size, from, e := conn.ReadFromUDP(buf)
			if e != nil {
				return
			}
			if size != 64 || from.IP.String() != "10.6.9.2" || ctx.Err() != nil || !guard() {
				continue
			}
			b := buf[:size]
			if string(b[:8]) != "USBLRTT1" || !hmac.Equal(b[8:24], n) {
				continue
			}
			seq := binary.BigEndian.Uint64(b[24:32])
			if seq >= 12000 || seen[seq] {
				continue
			}
			mac := hmac.New(sha256.New, k)
			mac.Write(b[:48])
			if !hmac.Equal(b[48:], mac.Sum(nil)[:16]) {
				continue
			}
			now := time.Now()
			tokens = math.Min(32, tokens+now.Sub(last).Seconds()*100)
			last = now
			if tokens < 1 {
				continue
			}
			tokens--
			seen[seq] = true
			conn.SetWriteDeadline(now.Add(time.Second))
			if _, e = conn.WriteToUDP(b, from); e != nil {
				return
			}
		}
	}()
	return nil
}
