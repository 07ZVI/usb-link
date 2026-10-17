//go:build usblink_local_remote

package connectioninstall

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
)

// The transport permits only installation and the fixed read-only archive API.
func localRemoteHandler(api http.Handler, generationActive func() bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Host != "10.6.9.1:47775" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			http.Error(w, "authenticated local USB request required", http.StatusForbidden)
			return
		}
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || peer != "10.6.9.2" || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || generationActive == nil || !generationActive() {
			http.Error(w, "verified USB peer required", http.StatusForbidden)
			return
		}
		allowed := r.Method == "GET" && (r.URL.Path == "/v1/restart" || r.URL.Path == "/v1/status" || r.URL.Path == "/v1/diagnostics/index") || r.Method == "POST" && (r.URL.Path == "/v1/restart" || r.URL.Path == "/v1/prepare" || r.URL.Path == "/v1/apply" || r.URL.Path == "/v1/cancel" || r.URL.Path == "/v1/diagnostics/chunk")
		if !allowed || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		api.ServeHTTP(w, r)
	})
}
