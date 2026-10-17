//go:build usblink_local_remote

package connectioninstall

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalRestartHTTPAdmission(t *testing.T) {
	token := strings.Repeat("a", 64)
	id := strings.Repeat("b", 32)
	cases := []struct {
		name, method, body, auth string
		active                   bool
		want, calls              int
	}{
		{"request", "POST", `{"id":"` + id + `"}`, token, true, 200, 1},
		{"status", "GET", "", token, true, 200, 0},
		{"off", "POST", `{"id":"` + id + `"}`, token, false, 403, 0},
		{"wrong_token", "POST", `{"id":"` + id + `"}`, strings.Repeat("c", 64), true, 403, 0},
		{"command_injection", "POST", `{"id":"` + id + `","command":"cmd.exe"}`, token, true, 400, 0},
		{"duplicate", "POST", `{"id":"` + id + `","id":"` + id + `"}`, token, true, 400, 0},
		{"path_id", "POST", `{"id":"../file"}`, token, true, 400, 0},
		{"put", "PUT", "", token, true, 404, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := 0
			api := localRestartAPI{status: func() (LocalRestartStatus, error) { return LocalRestartStatus{Phase: "idle"}, nil }, request: func(got string) (LocalRestartStatus, error) {
				n++
				if got != id {
					t.Fatal("id altered")
				}
				return LocalRestartStatus{ID: got, Phase: "prepared"}, nil
			}}
			h := localRemoteHandler(localRestartHandler(http.NotFoundHandler(), token, func() bool { return c.active }, api), func() bool { return c.active })
			r := httptest.NewRequest(c.method, "https://10.6.9.1:47775/v1/restart", strings.NewReader(c.body))
			r.RemoteAddr = "10.6.9.2:50000"
			r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
			r.Header.Set("Authorization", "Bearer "+c.auth)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.want || n != c.calls {
				t.Fatalf("code=%d calls=%d body=%s", w.Code, n, w.Body.String())
			}
		})
	}
}

func TestLocalRestartStatusRevocationDuringRead(t *testing.T) {
	active := true
	token := strings.Repeat("a", 64)
	api := localRestartAPI{status: func() (LocalRestartStatus, error) { active = false; return LocalRestartStatus{Phase: "idle"}, nil }}
	h := localRestartHandler(http.NotFoundHandler(), token, func() bool { return active }, api)
	r := httptest.NewRequest("GET", "https://10.6.9.1:47775/v1/restart", nil)
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || strings.Contains(w.Body.String(), `"phase"`) {
		t.Fatal("revoked generation exposed status")
	}
}
