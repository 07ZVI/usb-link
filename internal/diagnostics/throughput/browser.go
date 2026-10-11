package throughput

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"suhang/usbnet/internal/buildinfo"
)

//go:embed browser.html
var browserPage string

// NewBrowser retains the iPad entry; both devices can measure in their existing
// browser without installing or running a native test responder.
func NewBrowser(ctx context.Context, peer, host string, guard func() bool, changed func(Report)) (*Server, error) {
	return NewBrowserForDevice(ctx, "iPad", peer, host, guard, changed)
}

func NewBrowserForDevice(ctx context.Context, device, peer, host string, guard func() bool, changed func(Report)) (*Server, error) {
	if device != "Mac" && device != "iPad" {
		return nil, fmt.Errorf("unsupported browser measurement device")
	}
	if host == "" {
		return nil, fmt.Errorf("browser measurement host required")
	}
	s, e := New(ctx, peer, guard, changed)
	if e != nil {
		return nil, e
	}
	s.browserHost = host
	s.browserDevice = device
	return s, nil
}
func (s *Server) browserCommand() NativeCommand {
	return NativeCommand{Token: s.token, Chunk: ChunkBytes, Streams: Streams, Seconds: 10, MaxBytes: MaxDirectionBytes}
}
func (s *Server) browserPage(w http.ResponseWriter) {
	config, _ := json.Marshal(s.browserCommand())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-USB-Link-Version", buildinfo.Version)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+s.token+"'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	page := strings.ReplaceAll(browserPage, "__NONCE__", s.token)
	page = strings.ReplaceAll(page, "__DEVICE__", s.browserDevice)
	page = strings.Replace(page, "__CONFIG__", string(config), 1)
	w.Write([]byte(page))
}
func (s *Server) startBrowser(w http.ResponseWriter) {
	if e := s.startTest(true); e != nil {
		http.Error(w, e.Error(), 409)
		return
	}
	s.mu.Lock()
	v := s.browserCommand()
	v.ID = s.run.id
	s.mu.Unlock()
	writeJSON(w, v)
}
