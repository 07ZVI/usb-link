package remoteupdate

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPerformanceUsesExistingAuthenticationAndUpdateGate(t *testing.T) {
	calls := 0
	s := &Server{Token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Performance: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) })}
	request := func(token, origin string, tlsOn bool) int {
		q := httptest.NewRequest("POST", "https://10.6.9.1/v1/performance", nil)
		q.Header.Set("Authorization", "Bearer "+token)
		q.Header.Set("Origin", origin)
		if tlsOn {
			q.TLS = &tls.ConnectionState{}
		} else {
			q.TLS = nil
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, q)
		return w.Code
	}
	if request("bad", "", true) != 403 || request(s.Token, "https://foreign.invalid", true) != 403 || request(s.Token, "", false) != 403 || calls != 0 {
		t.Fatal("capture escaped authentication")
	}
	if request(s.Token, "", true) != 204 || calls != 1 {
		t.Fatal("authenticated capture failed")
	}
	s.job = "pending"
	if request(s.Token, "", true) != 409 || calls != 1 {
		t.Fatal("capture during pending update")
	}
}
