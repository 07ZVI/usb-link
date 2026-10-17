//go:build usblink_local_remote

package connectioninstall

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
)

type localDiagnosticArchive struct {
	index func() ([]byte, error)
	chunk func(string, int64, int, string) ([]byte, error)
}

// Archive callbacks expose only opaque catalog IDs; no client path reaches disk.
func localArchiveHandler(next http.Handler, token string, active func() bool, archive localDiagnosticArchive) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isIndex := r.Method == http.MethodGet && r.URL.Path == "/v1/diagnostics/index"
		isChunk := r.Method == http.MethodPost && r.URL.Path == "/v1/diagnostics/chunk"
		if !isIndex && !isChunk {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.Header.Get("Origin") != "" || len(token) != 64 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 || active == nil || !active() {
			http.Error(w, "local archive authorization required", http.StatusForbidden)
			return
		}
		if archive.index == nil || archive.chunk == nil {
			http.NotFound(w, r)
			return
		}
		var data []byte
		var err error
		if isIndex {
			if r.ContentLength > 0 {
				http.Error(w, "invalid archive request", http.StatusBadRequest)
				return
			}
			data, err = archive.index()
		} else {
			var q struct {
				ID     string `json:"id"`
				Offset int64  `json:"offset"`
				Length int    `json:"length"`
				SHA256 string `json:"expected_sha256"`
			}
			body, e := io.ReadAll(io.LimitReader(r.Body, 1025))
			d := json.NewDecoder(bytes.NewReader(body))
			d.DisallowUnknownFields()
			var extra any
			if e != nil || len(body) > 1024 || d.Decode(&q) != nil || d.Decode(&extra) != io.EOF || !localArchiveHex(q.ID, 32) || !localArchiveHex(q.SHA256, 64) || q.Offset < 0 || q.Length < 1 || q.Length > 32768 {
				http.Error(w, "invalid archive request", http.StatusBadRequest)
				return
			}
			data, err = archive.chunk(q.ID, q.Offset, q.Length, q.SHA256)
		}
		// Buffer the entire bounded reply before checking revocation again.
		if !active() {
			http.Error(w, "local archive authorization changed", http.StatusForbidden)
			return
		}
		if err != nil {
			status := http.StatusConflict
			if isIndex {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, "archive snapshot unavailable", status)
			return
		}
		if len(data) > 64*1024 || !json.Valid(data) {
			http.Error(w, "invalid archive response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})
}
func localArchiveHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
