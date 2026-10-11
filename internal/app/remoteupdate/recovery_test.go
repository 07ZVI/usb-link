package remoteupdate

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecoverySelfTestRequiresAuthenticatedEmptyIdleRequest(t *testing.T) {
	token := strings.Repeat("a", 64)
	calls := 0
	s := &Server{Version: "0.8.34", Token: token, RecoveryTest: func() error { calls++; return nil }}
	request := func(method, path, bearer, body string, tlsEnabled bool) int {
		q := httptest.NewRequest(method, path, strings.NewReader(body))
		q.Header.Set("Authorization", "Bearer "+bearer)
		if tlsEnabled {
			q.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, q)
		return w.Code
	}
	if request("POST", "/v1/recovery-test", token, "", false) != 403 || request("POST", "/v1/recovery-test", "wrong", "", true) != 403 {
		t.Fatal("unauthenticated test")
	}
	if request("POST", "/v1/recovery-test?seconds=900", token, "", true) != 400 || request("POST", "/v1/recovery-test", token, "{}", true) != 400 {
		t.Fatal("caller can change bounded operation")
	}
	if request("GET", "/v1/recovery-test", token, "", true) != 404 {
		t.Fatal("GET mutated state")
	}
	s.staging = true
	if request("POST", "/v1/recovery-test", token, "", true) != 409 {
		t.Fatal("overlapped upload")
	}
	s.staging = false
	s.job = "pending"
	if request("POST", "/v1/recovery-test", token, "", true) != 409 {
		t.Fatal("overlapped job")
	}
	s.job = ""
	if calls != 0 {
		t.Fatal("rejected request executed callback")
	}
	if request("POST", "/v1/recovery-test", token, "", true) != http.StatusOK || calls != 1 {
		t.Fatal("test not scheduled")
	}
	s.RecoveryTest = nil
	if request("POST", "/v1/recovery-test", token, "", true) != 404 {
		t.Fatal("unconfigured endpoint active")
	}
}
