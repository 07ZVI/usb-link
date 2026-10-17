//go:build usblink_local_remote

package macconnection

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalInvitationRequiresOwnedMacAndExplicitEnable(t *testing.T) {
	old := LocalMaintenanceInvitation
	defer func() { LocalMaintenanceInvitation = old }()
	enabled, owned := false, true
	LocalMaintenanceInvitation = func() string {
		if enabled {
			return `{"token":"private"}`
		}
		return ""
	}
	handler := localMaintenanceHandler(http.NotFoundHandler(), func() bool { return owned })
	call := func(peer, host, origin, method string) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, "http://10.6.9.1:10690/maintenance/connection", nil)
		q.RemoteAddr = peer
		q.Host = host
		q.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, q)
		return w
	}
	if call("10.6.9.2:1234", "10.6.9.1:10690", "", "GET").Code != 403 {
		t.Fatal("disabled invitation leaked")
	}
	enabled = true
	for _, tc := range []struct{ peer, host, origin, method string }{
		{"10.6.9.3:1", "10.6.9.1:10690", "", "GET"},
		{"192.168.1.2:1", "10.6.9.1:10690", "", "GET"},
		{"10.6.9.2:1", "evil.invalid", "", "GET"},
		{"10.6.9.2:1", "10.6.9.1:10690", "https://evil.invalid", "GET"},
		{"10.6.9.2:1", "10.6.9.1:10690", "", "POST"},
	} {
		if call(tc.peer, tc.host, tc.origin, tc.method).Code != 403 {
			t.Fatal(tc)
		}
	}
	w := call("10.6.9.2:1", "10.6.9.1:10690", "", "GET")
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w)
	}
	owned = false
	if call("10.6.9.2:1", "10.6.9.1:10690", "", "GET").Code != 403 {
		t.Fatal("lost USB ownership accepted")
	}
}
