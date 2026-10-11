// Package usbservice serves USB network diagnostics.
package usbservice

import (
	"net"
	"net/http"
	"strings"
)

type Handler struct {
	PeerIP    string
	Guard     func() bool
	Benchmark http.Handler
}

func (r *Handler) ServeHTTP(w http.ResponseWriter, q *http.Request) {
	peer, _, err := net.SplitHostPort(q.RemoteAddr)
	if err != nil || peer != r.PeerIP || r.Guard == nil || !r.Guard() {
		http.Error(w, "USB peer required", http.StatusForbidden)
		return
	}
	if r.Benchmark != nil && strings.HasPrefix(q.URL.Path, "/speed/") {
		r.Benchmark.ServeHTTP(w, q)
		return
	}
	http.NotFound(w, q)
}
