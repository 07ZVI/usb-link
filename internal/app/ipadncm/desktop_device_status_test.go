package ipadncm

import (
	"strings"
	"testing"
)

func TestDesktopPeerAddressDoesNotPresentPlannedOrStaleAddressAsAssigned(t *testing.T) {
	for _, tc := range []struct {
		name           string
		r              ApplicationResult
		stopping       bool
		address, state string
	}{
		{"ipad planned", ApplicationResult{DeviceKind: "iPad", Status: "USB_APPLICATION_TRIAL_RUNNING", ProposedIPadIPv4: "10.6.9.3"}, false, "", "尚未分配"},
		{"ipad acknowledged", ApplicationResult{DeviceKind: "iPad", Status: "USB_APPLICATION_TRIAL_RUNNING", ProposedIPadIPv4: "10.6.9.3", DHCPACKs: 1}, false, "10.6.9.3", "待確認"},
		{"ipad observed", ApplicationResult{DeviceKind: "iPad", Status: "USB_APPLICATION_TRIAL_RUNNING", ProposedIPadIPv4: "10.6.9.3", PeerIPv4NeighborVerified: true}, false, "10.6.9.3", "已確認"},
		{"ipad declined", ApplicationResult{DeviceKind: "iPad", Status: "USB_APPLICATION_TRIAL_RUNNING", ProposedIPadIPv4: "10.6.9.3", DHCPACKs: 1, DHCPDeclined: true}, false, "", "尚未分配"},
		{"ipad detached", ApplicationResult{DeviceKind: "iPad", Status: "MONITOR_WAITING", ProposedIPadIPv4: "10.6.9.3", PeerIPv4NeighborVerified: true}, false, "", "尚未分配"},
		{"mac planned", ApplicationResult{DeviceKind: "Mac", Status: "MAC_RUNNING"}, false, "", "尚未分配"},
		{"mac acknowledged", ApplicationResult{DeviceKind: "Mac", Status: "MAC_RUNNING", MacDHCPACKs: 1}, false, "10.6.9.2", "待確認"},
		{"mac observed", ApplicationResult{DeviceKind: "Mac", Status: "MAC_RUNNING", MacPeerResolved: true}, false, "10.6.9.2", "已確認"},
		{"mac paused", ApplicationResult{DeviceKind: "Mac", Status: "MONITOR_PAUSED", MacPeerResolved: true}, false, "", "尚未分配"},
		{"mac stopping", ApplicationResult{DeviceKind: "Mac", Status: "MAC_RUNNING", MacPeerResolved: true}, true, "", "尚未分配"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := desktopDeviceStatus(tc.r, tc.stopping)
			if status["peer_ipv4"] != tc.address || status["peer_address_state"] != tc.state {
				t.Fatalf("address=%v state=%v", status["peer_ipv4"], status["peer_address_state"])
			}
		})
	}
}

func TestDesktopCardRetryTargetsOnlyTheRequestedDevice(t *testing.T) {
	results := []ApplicationResult{{DeviceKind: "Mac", Status: "MONITOR_PAUSED"}, {DeviceKind: "iPad", Status: "MONITOR_RETRYING"}}
	for _, kind := range []string{"Mac", "iPad"} {
		var requested []string
		if !desktopRetryDevices(results, kind, func(device string) { requested = append(requested, device) }) || len(requested) != 1 || requested[0] != kind {
			t.Fatalf("%s card retried %v", kind, requested)
		}
	}
	results[0].Status = "MAC_RUNNING"
	if desktopRetryDevices(results, "Mac", func(string) { t.Fatal("active Mac must not be restarted by iPad recovery") }) {
		t.Fatal("active Mac reported retried")
	}
}

func TestDesktopDisplaysBothSessionsWithoutSelection(t *testing.T) {
	displaySessions.Lock()
	oldStates, oldSelected, oldManual := displaySessions.states, displaySessions.selected, displaySessions.manual
	mac := &applicationState{r: ApplicationResult{DeviceKind: "Mac", Status: "MAC_RUNNING", ObservedTransmitMbps: 800, USBSpeed: "SuperSpeed", ServicesReady: true}}
	ipad := &applicationState{r: ApplicationResult{DeviceKind: "iPad", Status: "USB_APPLICATION_TRIAL_RUNNING", ObservedTransmitMbps: 160, BenchmarkURL: "http://10.6.9.1:1234/"}}
	displaySessions.states = map[string]*applicationState{"Mac": mac, "iPad": ipad}
	displaySessions.selected, displaySessions.manual = "iPad", true
	displaySessions.Unlock()
	t.Cleanup(func() {
		displaySessions.Lock()
		displaySessions.states, displaySessions.selected, displaySessions.manual = oldStates, oldSelected, oldManual
		displaySessions.Unlock()
	})
	r := deviceDisplaySnapshots()
	if len(r) != 2 || r[0].DeviceKind != "Mac" || r[1].DeviceKind != "iPad" {
		t.Fatal("both slots required in stable order", r)
	}
	m, i := desktopDeviceStatus(r[0], false), desktopDeviceStatus(r[1], false)
	if m["tx"] != float64(800) || i["tx"] != float64(160) || m["benchmark_available"] != true || i["benchmark_available"] != true || i["benchmark_url"] != "http://10.6.9.1:1234/" || m["benchmark_url"] != "http://10.6.9.1:10690/speed/" || m["benchmark_ready"] != false {
		t.Fatal("device-specific traffic or benchmark state crossed sessions", m, i)
	}
	ipad.update(func(r *ApplicationResult) { r.Status = "MONITOR_WAITING"; r.ObservedTransmitMbps = 0 })
	r = deviceDisplaySnapshots()
	if desktopDeviceStatus(r[0], false)["connected"] != true || desktopDeviceStatus(r[1], false)["connected"] != false || r[0].ObservedTransmitMbps != 800 {
		t.Fatal("iPad detach changed Mac display")
	}
	displaySessions.Lock()
	delete(displaySessions.states, "iPad")
	displaySessions.Unlock()
	r = deviceDisplaySnapshots()
	if r[1].DeviceKind != "iPad" || r[1].Status != "MONITOR_WAITING" || r[1].ObservedTransmitMbps != 0 {
		t.Fatal("missing session must display a waiting slot without stale traffic")
	}
}

func TestDesktopConnectionColorsFollowPeerEvidenceAndRecovery(t *testing.T) {
	for _, tc := range []struct {
		r        ApplicationResult
		stopping bool
		want     string
	}{
		{ApplicationResult{DeviceKind: "Mac", Status: "MONITOR_WAITING", Error: "old error"}, false, "offline"},
		{ApplicationResult{DeviceKind: "Mac", Status: "MAC_RUNNING"}, false, "connecting"},
		{ApplicationResult{DeviceKind: "Mac", Status: "MAC_RUNNING", MacPeerResolved: true}, false, "connected"},
		{ApplicationResult{DeviceKind: "iPad", Status: "USB_APPLICATION_TRIAL_RUNNING", DHCPACKs: 1}, false, "connecting"},
		{ApplicationResult{DeviceKind: "iPad", Status: "USB_APPLICATION_TRIAL_RUNNING", HTTPVerified: true}, false, "connected"},
		{ApplicationResult{DeviceKind: "iPad", Status: "MONITOR_RETRYING", Error: "recoverable"}, false, "connecting"},
		{ApplicationResult{DeviceKind: "iPad", Status: "MONITOR_PAUSED", Error: "failed"}, false, "error"},
		{ApplicationResult{DeviceKind: "Mac", Status: "USB_RECOVERY_MAINTENANCE"}, false, "error"},
		{ApplicationResult{DeviceKind: "Mac", Status: "MAC_RUNNING", MacPeerResolved: true}, true, "offline"},
	} {
		if got := desktopDeviceStatus(tc.r, tc.stopping)["connection_state"]; got != tc.want {
			t.Fatalf("%s stopping=%v got=%s want=%s", tc.r.Status, tc.stopping, got, tc.want)
		}
	}
}

func TestMacBrowserLinkRequiresActiveServicesAndNeverDependsOnNativePolling(t *testing.T) {
	for _, tc := range []struct {
		status                   string
		services, stopping, want bool
	}{
		{"MAC_RUNNING", true, false, true}, {"MAC_RUNNING", false, false, false}, {"MONITOR_WAITING", true, false, false}, {"MAC_RUNNING", true, true, false},
	} {
		v := desktopDeviceStatus(ApplicationResult{DeviceKind: "Mac", Status: tc.status, ServicesReady: tc.services, BenchmarkURL: "stale"}, tc.stopping)
		if (v["benchmark_url"] != "") != tc.want || v["benchmark_available"] != tc.want {
			t.Fatal("incorrect browser link availability", v)
		}
		if strings.Contains(v["benchmark_summary"].(string), "測試程式尚未啟動") {
			t.Fatal("native dependency in browser flow")
		}
	}
}
