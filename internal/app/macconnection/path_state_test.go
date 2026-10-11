package macconnection

import "testing"

func TestPathStateReportsFallbackAndCacheFailure(t *testing.T) {
	for _, row := range []struct {
		line    string
		mtu     int
		healthy bool
	}{
		{"2026/10/07 12:00:00 USB_MAC_PATH_STATE mtu=1500 healthy=true", 1500, true},
		{"USB_MAC_PATH_STATE mtu=9000 healthy=false", 9000, false},
		{"USB_MAC_PATH_STATE mtu=16000 healthy=true", 16000, true},
	} {
		mtu, healthy, ok := parsePathState(row.line)
		if !ok || mtu != row.mtu || healthy != row.healthy {
			t.Fatalf("%s: %d %t %t", row.line, mtu, healthy, ok)
		}
	}
	for _, line := range []string{"USB_MAC_PATH_STATE mtu=65535 healthy=true", "USB_MAC_PATH_STATE mtu=9000 healthy=true healthy=false", "USB_MAC_PATH_STATE mtu=9000 healthy=1", "MTU_TRIAL_RESULT effective_mtu=9000", "USB_MAC_PATH_STATE mtu=9000"} {
		if _, _, ok := parsePathState(line); ok {
			t.Fatalf("malformed state accepted: %s", line)
		}
	}
}
