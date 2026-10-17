//go:build usblink_local_remote

package connectioninstall

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

func localInstallIDValid(id string) bool {
	return len(id) == 32 && strings.Trim(id, "0123456789abcdef") == ""
}

func localInstallConsent(token string) string {
	if len(token) != 64 {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func localInstallAuthorized(enabled bool, hash, captured string, deadline int64, now time.Time) bool {
	return enabled && len(captured) == 64 && hash == captured && deadline > now.Unix() && deadline <= now.Add(2*time.Minute).Unix()
}

func localInstallCancelable(status string) bool {
	return status == "staged" || status == "awaiting_local_admin"
}

func localInstallTerminal(status string) bool {
	return status == "complete" || status == "cancelled" || status == "failed"
}
