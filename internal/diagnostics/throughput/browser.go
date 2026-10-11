package throughput

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"
)

//go:embed browser.html
var browserPage string

// NewBrowser is used only by the iPad USB application session. Mac sessions
// continue to use New and never expose the browser page or browser start API.
func NewBrowser(ctx context.Context, peer, host string, guard func() bool, changed func(Report)) (*Server, error) {
	s, e := New(ctx, peer, guard, changed)
	if e != nil {
		return nil, e
	}
	s.browserHost = host
	return s, nil
}
func (s *Server) browserCommand() NativeCommand {
	return NativeCommand{Token: s.token, Chunk: ChunkBytes, Streams: Streams, Seconds: 10, MaxBytes: MaxDirectionBytes}
}
func (s *Server) browserPage(w http.ResponseWriter) {
	config, _ := json.Marshal(s.browserCommand())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+s.token+"'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	page := strings.ReplaceAll(browserPage, "__NONCE__", s.token)
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
