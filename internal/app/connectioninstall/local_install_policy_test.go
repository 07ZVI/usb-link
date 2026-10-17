//go:build usblink_local_remote

package connectioninstall

import (
	"strings"
	"testing"
	"time"
)

func TestLocalInstallAuthorizationDoesNotSurviveCredentialRotation(t *testing.T) {
	now := time.Unix(1000, 0)
	token := strings.Repeat("a", 64)
	captured := localInstallConsent(token)
	for _, c := range []struct {
		name     string
		enabled  bool
		token    string
		deadline int64
		want     bool
	}{
		{"active", true, token, 1100, true},
		{"disabled", false, token, 1100, false},
		{"rotated", true, strings.Repeat("b", 64), 1100, false},
		{"expired", true, token, 1000, false},
		{"unbounded", true, token, 1121, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := localInstallAuthorized(c.enabled, localInstallConsent(c.token), captured, c.deadline, now); got != c.want {
				t.Fatal(got)
			}
		})
	}
}

func TestLocalInstallArgumentsAndCancellationAreBounded(t *testing.T) {
	for _, id := range []string{"", "../setup.exe", strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("a", 31) + " "} {
		if localInstallIDValid(id) {
			t.Fatalf("accepted %q", id)
		}
	}
	if !localInstallIDValid(strings.Repeat("a", 32)) {
		t.Fatal("valid ID rejected")
	}
	for _, status := range []string{"dispatching", "installing", "complete", "failed", "unknown"} {
		if localInstallCancelable(status) {
			t.Fatalf("cancelled %s after handoff", status)
		}
	}
}
