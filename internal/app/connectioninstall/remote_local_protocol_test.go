//go:build usblink_local_remote

package connectioninstall

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
	"testing"
)

func TestLocalRemoteTransportRejectsOtherPeersAndCapabilities(t *testing.T) {
	for _, tc := range []struct {
		method, path, peer string
		tlsVersion         uint16
		generation         bool
		want               int
	}{
		{"GET", "/v1/status", "10.6.9.2:50000", tls.VersionTLS13, true, 200},
		{"GET", "/v1/diagnostics/index", "10.6.9.2:50000", tls.VersionTLS13, true, 200},
		{"POST", "/v1/diagnostics/chunk", "10.6.9.2:50000", tls.VersionTLS13, true, 200},
		{"GET", "/v1/diagnostics/chunk", "10.6.9.2:50000", tls.VersionTLS13, true, 404},
		{"GET", "/v1/diagnostics/index?path=private", "10.6.9.2:50000", tls.VersionTLS13, true, 404},
		{"POST", "/v1/prepare", "10.6.9.2:50000", tls.VersionTLS13, true, 200},
		{"POST", "/v1/apply", "10.6.9.2:50000", tls.VersionTLS13, true, 200},
		{"POST", "/v1/cancel", "10.6.9.2:50000", tls.VersionTLS13, true, 200},
		{"GET", "/v1/status", "10.6.9.3:50000", tls.VersionTLS13, true, 403},
		{"GET", "/v1/status", "127.0.0.1:50000", tls.VersionTLS13, true, 403},
		{"GET", "/v1/status", "10.6.9.2:50000", tls.VersionTLS12, true, 403},
		{"GET", "/v1/status", "10.6.9.2:50000", tls.VersionTLS13, false, 403},
		{"POST", "/v1/performance", "10.6.9.2:50000", tls.VersionTLS13, true, 404},
		{"POST", "/v1/recovery-test", "10.6.9.2:50000", tls.VersionTLS13, true, 404},
		{"POST", "/v1/filedrop", "10.6.9.2:50000", tls.VersionTLS13, true, 404},
		{"GET", "/v1/status?token=ignored", "10.6.9.2:50000", tls.VersionTLS13, true, 404},
	} {
		called := false
		h := localRemoteHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) }), func() bool { return tc.generation })
		r := httptest.NewRequest(tc.method, "https://10.6.9.1:47775"+tc.path, nil)
		r.RemoteAddr, r.TLS = tc.peer, &tls.ConnectionState{Version: tc.tlsVersion}
		r.Header.Set("Authorization", "Bearer test")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want || called != (tc.want == 200) {
			t.Fatalf("%+v status=%d called=%v", tc, w.Code, called)
		}
	}
}

func TestLocalRemoteTransportRetainsBearerAndOriginChecks(t *testing.T) {
	token := strings.Repeat("a", 64)
	api := &remoteupdate.Server{Version: "0.10.19", Token: token, Status: func() any { return map[string]string{"status": "idle"} }}
	h := localRemoteHandler(api, func() bool { return true })
	for _, tc := range []struct {
		authorization, origin string
		want                  int
	}{
		{"Bearer " + token, "", 200},
		{"", "", 403},
		{token, "", 403},
		{"Bearer " + strings.Repeat("b", 64), "", 403},
		{"Bearer " + token, "https://example.com", 403},
	} {
		r := httptest.NewRequest("GET", "https://10.6.9.1:47775/v1/status", nil)
		r.RemoteAddr, r.TLS = "10.6.9.2:50000", &tls.ConnectionState{Version: tls.VersionTLS13}
		r.Header.Set("Authorization", tc.authorization)
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("authorization outcome=%d want=%d", w.Code, tc.want)
		}
	}
}
