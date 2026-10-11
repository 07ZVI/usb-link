package ipadncm

import (
	"strings"
	"testing"
)

func TestMacCacheFailureIsVisibleWithoutDisconnectClaim(t *testing.T) {
	r := ApplicationResult{DeviceKind: "Mac", Status: "MAC_RUNNING", MacPeerResolved: true, MacPathMTUWarning: "USB_MAC_PATH_CACHE_REFRESH_FAILED"}
	title, _, detail := applicationView(r, false)
	if !strings.Contains(title, "速度可能下降") || !strings.Contains(detail, "重新連接 USB") || strings.Contains(title, "停止") {
		t.Fatalf("%s / %s", title, detail)
	}
	r.MacPathMTUWarning = ""
	title, _, detail = applicationView(r, false)
	if strings.Contains(title, "速度可能下降") || strings.Contains(detail, "未完整刷新") {
		t.Fatal("resolved warning remained visible")
	}
}
