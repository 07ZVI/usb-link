//go:build windows && amd64 && !usblink_local_remote

package macconnection

import "net/http"

func localMaintenanceHandler(next http.Handler, _ func() bool) http.Handler { return next }
