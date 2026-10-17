//go:build usblink_local_remote

package connectioninstall

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
)

type localRestartAPI struct {
	status  func() (LocalRestartStatus, error)
	request func(string) (LocalRestartStatus, error)
}

func localRestartHandler(next http.Handler, token string, active func() bool, api localRestartAPI) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/restart" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.Header.Get("Origin") != "" || len(token) != 64 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 || active == nil || !active() {
			http.Error(w, "restart authorization required", 403)
			return
		}
		var status LocalRestartStatus
		var err error
		switch r.Method {
		case "GET":
			if r.ContentLength != 0 {
				http.Error(w, "invalid restart request", 400)
				return
			}
			status, err = api.status()
		case "POST":
			b, e := io.ReadAll(io.LimitReader(r.Body, 257))
			var q struct {
				ID string `json:"id"`
			}
			if e != nil || len(b) > 256 || !coreExactFields(b, []string{"id"}) || json.Unmarshal(b, &q) != nil || !localArchiveHex(q.ID, 32) {
				http.Error(w, "invalid restart request", 400)
				return
			}
			if !active() {
				http.Error(w, "restart authorization changed", 403)
				return
			}
			status, err = api.request(q.ID)
		default:
			http.NotFound(w, r)
			return
		}
		if r.Method == "GET" && !active() {
			http.Error(w, "restart authorization changed", 403)
			return
		}
		if err != nil {
			http.Error(w, "LOCAL_RESTART_UNAVAILABLE", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	})
}
