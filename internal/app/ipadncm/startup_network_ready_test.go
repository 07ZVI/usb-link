package ipadncm

import "testing"

func TestStartupReadinessRequiresCurrentNetworkProof(t *testing.T) {
	mac := ApplicationResult{DeviceKind: "Mac", Status: "MAC_RUNNING", WindowsIPv4: "10.6.9.1", MacPeerResolved: true, ServicesReady: true}
	ipad := ApplicationResult{DeviceKind: "iPad", Status: "USB_APPLICATION_TRIAL_RUNNING", WindowsIPv4: "10.6.9.1", DHCPStarted: true, PeerIPv4NeighborVerified: true}
	for _, valid := range []ApplicationResult{mac, ipad} {
		if !startupNetworkReady(valid) {
			t.Fatalf("valid proof rejected: %s", valid.DeviceKind)
		}
		for _, status := range []string{"WAITING_SHARED_HOST", "MONITOR_WAITING", "USB_RECOVERY_MAINTENANCE", "USB_RECOVERY_WAITING", "MONITOR_PAUSED"} {
			stale := valid
			stale.Status = status
			if startupNetworkReady(stale) {
				t.Fatalf("stale proof accepted in %s", status)
			}
		}
		failed := valid
		failed.Error = "failed"
		if startupNetworkReady(failed) {
			t.Fatal("failed network accepted")
		}
		other := valid
		other.WindowsIPv4 = "10.6.10.1"
		if startupNetworkReady(other) {
			t.Fatal("fallback address accepted")
		}
	}
	ipad.PeerIPv4NeighborVerified = false
	ipad.DHCPACKs = 1
	if startupNetworkReady(ipad) {
		t.Fatal("DHCP ACK alone is not peer readiness")
	}
	mac.MacPeerResolved = false
	if startupNetworkReady(mac) {
		t.Fatal("listener alone is not Mac readiness")
	}
}
