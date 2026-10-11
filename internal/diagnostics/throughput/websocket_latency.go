package throughput

import (
	"context"
	"crypto/hmac"
	"encoding/binary"
	"net/http"
	"time"

	"golang.org/x/net/websocket"
)

// Browser WebSocket timing includes browser/TCP scheduling; it must never be
// reported as UDP loss, one-way video latency or the physical USB latency.
func (s *Server) browserLatency(w http.ResponseWriter, q *http.Request) {
	if s.browserHost == "" || q.Header.Get("Origin") != "http://"+s.browserHost || q.URL.RawQuery != "" {
		http.Error(w, "same-origin USB browser session required", 403)
		return
	}
	s.mu.Lock()
	if s.wsLatencyActive {
		s.mu.Unlock()
		http.Error(w, "latency test busy", 409)
		return
	}
	s.wsLatencyActive = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.wsLatencyActive = false; s.mu.Unlock() }()
	websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		stop := context.AfterFunc(s.ctx, func() { ws.Close() })
		defer stop()
		ws.MaxPayloadBytes = 128
		if ws.SetDeadline(time.Now().Add(3*time.Second)) != nil {
			return
		}
		var auth string
		if websocket.Message.Receive(ws, &auth) != nil || !hmac.Equal([]byte(auth), []byte("authorize:"+s.token)) {
			return
		}
		ws.MaxPayloadBytes = 64
		expires := time.Now().Add(120 * time.Second)
		if ws.SetDeadline(expires) != nil || websocket.Message.Send(ws, "ready") != nil {
			return
		}
		tokens := 20.0
		last := time.Now()
		var lastSeq uint32
		haveSeq := false
		for count := 0; count < 12000; count++ {
			var b []byte
			if websocket.Message.Receive(ws, &b) != nil || len(b) != 64 || string(b[4:12]) != "USBLWS01" || s.ctx.Err() != nil || s.guard == nil || !s.guard() {
				return
			}
			seq := binary.BigEndian.Uint32(b[:4])
			if seq >= 12000 || (haveSeq && seq <= lastSeq) {
				return
			}
			lastSeq = seq
			haveSeq = true
			now := time.Now()
			tokens += now.Sub(last).Seconds() * 100
			if tokens > 20 {
				tokens = 20
			}
			last = now
			if tokens < 1 || now.After(expires) {
				return
			}
			tokens--
			if websocket.Message.Send(ws, b) != nil {
				return
			}
		}
	}).ServeHTTP(w, q)
}
