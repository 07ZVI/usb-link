package throughput

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"
)

var current struct {
	sync.Mutex
	s *Server
}

func SetCurrent(s *Server) { current.Lock(); current.s = s; current.Unlock() }
func Current() *Server     { current.Lock(); defer current.Unlock(); return current.s }

type NativeCommand struct {
	Token                   string `json:"token"`
	ID                      string `json:"id,omitempty"`
	Chunk, Streams, Seconds int
	MaxBytes                int64
}

func (s *Server) nativePoll(w http.ResponseWriter) {
	s.mu.Lock()
	s.nativeSeen = time.Now()
	v := NativeCommand{Token: s.token, Chunk: ChunkBytes, Streams: Streams, Seconds: 10, MaxBytes: MaxDirectionBytes}
	if s.run != nil && !s.nativeClaimed && s.run.report.Status == "download" && time.Now().Before(s.run.expires) {
		v.ID = s.run.id
		s.nativeClaimed = true
	}
	s.mu.Unlock()
	writeJSON(w, v)
}
func (s *Server) NativeState() (ready, busy bool, progress int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ready = !s.closed && s.ctx.Err() == nil && time.Since(s.nativeSeen) < 3*time.Second
	if s.run == nil {
		return
	}
	r := s.run
	busy = r.report.Status == "download" || r.report.Status == "upload"
	if busy {
		elapsed := time.Since(r.expires.Add(-sessionLifetime)).Seconds()
		progress = min(99, int(elapsed/22*100))
	} else if r.report.Status == "complete" {
		progress = 100
	}
	return
}
func (s *Server) StartNative() error { return s.startTest(false) }
func (s *Server) startTest(browser bool) error {
	if s == nil {
		return fmt.Errorf("原生測速對端尚未連接")
	}
	if s.ctx.Err() != nil || s.guard == nil || !s.guard() {
		return context.Canceled
	}
	s.mu.Lock()
	if s.closed || browser != (s.browserHost != "") || (!browser && time.Since(s.nativeSeen) >= 3*time.Second) {
		s.mu.Unlock()
		return fmt.Errorf("原生測速對端尚未連接")
	}
	if s.run != nil && (s.run.active > 0 || s.run.report.Status == "download" || s.run.report.Status == "upload") {
		s.mu.Unlock()
		return fmt.Errorf("測速已在進行")
	}
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		s.mu.Unlock()
		return e
	}
	s.run = &session{id: hex.EncodeToString(nonce[:]), expires: time.Now().Add(sessionLifetime), report: Report{Status: "download", StartedUTC: time.Now().UTC().Format(time.RFC3339), Method: "native HTTP/TCP payload; peer receiver download timing; server receiver upload timing; application RTT, no UDP loss measurement", Streams: Streams}}
	if browser {
		s.run.report.Method = "browser HTTP/TCP payload; peer receiver download timing; server receiver upload timing; includes browser overhead, no UDP loss measurement"
	}
	s.nativeClaimed = browser
	r := s.run.report
	s.mu.Unlock()
	s.notify(r)
	return nil
}
func (s *Server) CancelNative() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.run == nil || (s.run.report.Status != "download" && s.run.report.Status != "upload") {
		s.mu.Unlock()
		return
	}
	s.run.report.Status = "failed"
	s.run.report.Error = "使用者取消測試"
	r := s.run.report
	s.mu.Unlock()
	s.notify(r)
}

// NativeReport is read under the server lock, avoiding delayed UI callbacks.
func (s *Server) NativeReport() Report {
	if s == nil {
		return Report{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.run == nil {
		return Report{}
	}
	return s.run.report
}

var deviceServers = struct {
	sync.Mutex
	servers map[string]*Server
}{servers: map[string]*Server{}}

func SetDeviceCurrent(kind string, s *Server) {
	deviceServers.Lock()
	deviceServers.servers[kind] = s
	deviceServers.Unlock()
}
func DeviceCurrent(kind string) *Server {
	deviceServers.Lock()
	defer deviceServers.Unlock()
	return deviceServers.servers[kind]
}
