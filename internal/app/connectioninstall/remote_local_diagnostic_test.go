//go:build usblink_local_remote

package connectioninstall

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalArchiveAuthorizationAndRevocation(t *testing.T) {
	token := strings.Repeat("a", 64)
	for _, mode := range []string{"valid", "token", "origin", "tls", "revoke", "initial-off"} {
		t.Run(mode, func(t *testing.T) {
			active := mode != "initial-off"
			calls := 0
			h := localRemoteHandler(localArchiveHandler(http.NotFoundHandler(), token, func() bool { return active }, localDiagnosticArchive{
				index: func() ([]byte, error) {
					calls++
					if mode == "revoke" {
						active = false
					}
					return []byte(`{"archives":[]}`), nil
				}, chunk: func(string, int64, int, string) ([]byte, error) { return nil, nil },
			}), func() bool { return active })
			r := httptest.NewRequest("GET", "https://10.6.9.1:47775/v1/diagnostics/index", nil)
			r.RemoteAddr = "10.6.9.2:50000"
			r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
			r.Header.Set("Authorization", "Bearer "+token)
			if mode == "token" {
				r.Header.Set("Authorization", "Bearer "+strings.Repeat("b", 64))
			}
			if mode == "origin" {
				r.Header.Set("Origin", "https://example.com")
			}
			if mode == "tls" {
				r.TLS.Version = tls.VersionTLS12
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if mode == "valid" {
				if w.Code != 200 || calls != 1 {
					t.Fatal(w.Code, calls)
				}
			} else if w.Code != 403 || strings.Contains(w.Body.String(), "archives") || calls > 0 && mode != "revoke" {
				t.Fatal(w.Code, calls, w.Body.String())
			}
		})
	}
}
func TestLocalArchiveChunkRejectsPathsAndBounds(t *testing.T) {
	token := strings.Repeat("a", 64)
	called := 0
	h := localArchiveHandler(http.NotFoundHandler(), token, func() bool { return true }, localDiagnosticArchive{index: func() ([]byte, error) { return nil, nil }, chunk: func(id string, offset int64, length int, sha string) ([]byte, error) {
		called++
		return []byte(`{}`), nil
	}})
	for _, body := range []string{
		`{"id":"../../secret","offset":0,"length":1,"expected_sha256":"` + token + `"}`,
		`{"id":"` + strings.Repeat("b", 32) + `","offset":-1,"length":1,"expected_sha256":"` + token + `"}`,
		`{"id":"` + strings.Repeat("b", 32) + `","offset":0,"length":32769,"expected_sha256":"` + token + `"}`,
		`{"id":"` + strings.Repeat("b", 32) + `","offset":0,"length":1,"expected_sha256":"` + token + `","path":"private"}`,
		strings.Repeat(" ", 1025),
	} {
		r := httptest.NewRequest("POST", "https://10.6.9.1:47775/v1/diagnostics/chunk", strings.NewReader(body))
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 || called != 0 {
			t.Fatal(w.Code, called)
		}
	}
	body := `{"id":"` + strings.Repeat("b", 32) + `","offset":0,"length":32768,"expected_sha256":"` + token + `"}`
	r := httptest.NewRequest("POST", "https://10.6.9.1:47775/v1/diagnostics/chunk", strings.NewReader(body))
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || called != 1 {
		t.Fatal(w.Code, called)
	}
}
