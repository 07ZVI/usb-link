package throughput

import (
	"encoding/json"
	"io"
	"math"
	"net/http"
	"time"
)

func (s *Server) recordLatency(w http.ResponseWriter, q *http.Request) {
	var v struct {
		MS float64 `json:"ms"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, q.Body, 128))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || math.IsNaN(v.MS) || math.IsInf(v.MS, 0) || v.MS < 0 || v.MS > 15000 {
		http.Error(w, "invalid latency", 400)
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		http.Error(w, "invalid latency", 400)
		return
	}
	s.mu.Lock()
	s.latencyMS = v.MS
	s.latencyAt = time.Now()
	s.mu.Unlock()
	writeJSON(w, map[string]bool{"ok": true})
}
func (s *Server) LiveLatency() (float64, bool) {
	if s == nil {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latencyMS, !s.closed && s.ctx.Err() == nil && !s.latencyAt.IsZero() && time.Since(s.latencyAt) < 8*time.Second
}
