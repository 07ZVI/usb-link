package ipadncm

import (
	"strings"
	"testing"
)

func TestUnavailableSharedHostWaitsForBackgroundRecovery(t *testing.T) {
	title, _, detail := applicationView(ApplicationResult{Status: "MONITOR_PAUSED", Error: "APPLICATION_SHARED_HOST_UNAVAILABLE", SunshineClientTCPObserved: true, PeerIPv4NeighborVerified: true}, false)
	if !strings.Contains(title, "將自動繼續") || strings.Contains(title, "重試連線") || !strings.Contains(detail, "不需要重開程式") || !strings.Contains(detail, "並非目前連線") {
		t.Fatal(title, detail)
	}
}
