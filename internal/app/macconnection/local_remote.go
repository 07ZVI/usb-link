//go:build usblink_local_remote

package macconnection

import (
	"net"
	"net/http"
)

// LocalMaintenanceInvitation returns session credentials only to the owned Mac USB peer.
var LocalMaintenanceInvitation func() string

func localMaintenanceHandler(next http.Handler, guard func() bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/maintenance/connection" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		peer, _, _ := net.SplitHostPort(r.RemoteAddr)
		if peer != "10.6.9.2" || r.Method != "GET" || r.URL.RawQuery != "" || r.Header.Get("Origin") != "" || r.Host != "10.6.9.1:10690" || !guard() || LocalMaintenanceInvitation == nil {
			http.Error(w, "USB maintenance unavailable", 403)
			return
		}
		invitation := LocalMaintenanceInvitation()
		if invitation == "" {
			http.Error(w, "USB maintenance disabled", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(invitation))
	})
}
