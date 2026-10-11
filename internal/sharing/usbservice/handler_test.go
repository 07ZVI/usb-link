package usbservice

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRemovedEndpointsCannotTransferFilesOrDiscloseUpgradeCredentials(t *testing.T) {
	h := &Handler{PeerIP: "10.6.9.2", Guard: func() bool { return true }, Benchmark: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })}
	for _, path := range []string{"/upload", "/share", "/share/data.txt", "/maintenance/connection"} {
		for _, method := range []string{"GET", "POST", "PUT", "PROPFIND"} {
			req := httptest.NewRequest(method, path, nil)
			req.RemoteAddr = "10.6.9.2:50000"
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			if out.Code != 404 {
				t.Fatalf("%s %s: %d", method, path, out.Code)
			}
		}
	}
	req := httptest.NewRequest("GET", "/speed/", nil)
	req.RemoteAddr = "10.6.9.2:50000"
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != 204 {
		t.Fatal("network diagnostics lost", out.Code)
	}
	for _, peer := range []string{"192.168.1.4:50000", "10.6.9.2:50000"} {
		h.Guard = func() bool { return false }
		req.RemoteAddr = peer
		out = httptest.NewRecorder()
		h.ServeHTTP(out, req)
		if out.Code != 403 {
			t.Fatal("unauthorized diagnostics", out.Code)
		}
	}
}
