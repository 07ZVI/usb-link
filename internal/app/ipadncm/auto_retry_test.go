package ipadncm

import (
	"strings"
	"testing"
	"time"
)

func TestAutomaticRetryRecoversTransientSameAttachmentButIsBounded(t *testing.T) {
	var b autoRetryBudget
	for _, want := range []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second} {
		if got := b.delay("EXACT_ROOT_REENUMERATION_TIMEOUT", false); got != want {
			t.Fatal(got, want)
		}
		b.used++
	}
	if b.delay("", false) != 0 || b.delay("APPLE_USB_DEVICE_NOT_READY", true) != 0 {
		t.Fatal("unbounded restart loop")
	}
}
func TestAutomaticRetryNeverOverridesRefusalOrRecoveryFailure(t *testing.T) {
	var b autoRetryBudget
	for _, reason := range []string{"USB_UNEXPECTED_HID_INTERFACE", "USB_SECURITY_INVENTORY_UNAVAILABLE", "USB_SECURITY_ANCESTRY_UNAVAILABLE", "USB_SECURITY_ROOT_ABSENT", "MAC_CONNECTION_DECLINED_OR_CHANGED", "MAC_WINUSB_BINDING_FAILED", "MAC_EMBEDDED_RUNTIME_PREPARATION_FAILED", "MAC_BRIDGE_ENDED_WITH_ERROR", "INSTALL_DECLINED", "USB_LAYOUT_UNCONFIRMED_DECLINED_OR_CHANGED", "APPLE_SERVICE_RESTORE_NOT_CONFIRMED", "TARGET_WINDOWS_RESTART_REQUIRED", "APPLICATION_FIREWALL_SETUP_FAILED", "USB_CONNECTION_NOT_ALLOWED", "UNKNOWN_ERROR"} {
		if b.delay(reason, false) != 0 || b.delay(reason, true) != 0 {
			t.Fatal("unsafe retry", reason)
		}
	}
}

func TestMacReplugBeforeChildInterfacesReadyRecoversWithoutManualRetry(t *testing.T) {
	for _, reason := range []string{"MAC_EXACT_PAIR_UNAVAILABLE", "MAC_WINUSB_PAIR_NOT_READY"} {
		t.Run(reason, func(t *testing.T) {
			var budget autoRetryBudget
			var stable sameAttachmentGate
			start := time.Unix(100, 0)
			root := idlePresence{readable: true, candidate: true, identity: "mac-root"}
			// Run failed before Ready was set and no absence was observed after
			// cleanup. The same root must still recover when children arrive.
			if budget.delay(reason, false) != 5*time.Second || stable.ready(start, root.identity, root) {
				t.Fatal("late Mac interfaces have no bounded recovery")
			}
			if !stable.ready(start.Add(5*time.Second), root.identity, root) {
				t.Fatal("stable replug stranded")
			}
			budget.used = 3
			if budget.delay(reason, false) != 0 {
				t.Fatal("persistent interface failure retried indefinitely")
			}
		})
	}
}
func TestAutomaticRetryWaitsForStableSameDevice(t *testing.T) {
	var g sameAttachmentGate
	now := time.Unix(100, 0)
	p := idlePresence{readable: true, candidate: true, identity: "ipad-a"}
	if g.ready(now, "ipad-a", p) {
		t.Fatal("no debounce")
	}
	if !g.ready(now.Add(2*time.Second), "ipad-a", p) {
		t.Fatal("same ready device stranded")
	}
	if g.ready(now.Add(3*time.Second), "ipad-a", idlePresence{}) {
		t.Fatal("unreadable is not ready")
	}
	if g.ready(now.Add(5*time.Second), "ipad-a", p) {
		t.Fatal("stability not restarted")
	}
	p.identity = "mac-b"
	if g.ready(now.Add(9*time.Second), "ipad-a", p) {
		t.Fatal("identity crossed")
	}
}
func TestRecognizedDeviceIsNotShownAsConnected(t *testing.T) {
	r := ApplicationResult{DeviceKind: "iPad", Status: "MONITOR_PREPARING"}
	if !strings.Contains(connectionSubtitle(r), "正在準備") {
		t.Fatal(connectionSubtitle(r))
	}
	r.Status = "MONITOR_RETRYING"
	r.AutoRetryAttempt = 2
	r.AutoRetrySeconds = 15
	r.Error = "EXACT_ROOT_REENUMERATION_TIMEOUT"
	title, _, detail := applicationView(r, false)
	if !strings.Contains(title, "15 秒") || !strings.Contains(title, "2/3") || !strings.Contains(detail, r.Error) {
		t.Fatal(title, detail)
	}
	r.Status = "USB_APPLICATION_TRIAL_RUNNING"
	r.DHCPStarted = true
	if !strings.Contains(connectionSubtitle(r), "網路已啟動") {
		t.Fatal(connectionSubtitle(r))
	}
}

func TestPeerPreparationRetriesOnlyLateNetworkReadiness(t *testing.T) {
	for _, s := range []string{"PREFERRED_TARGET_IPV6_LINK_LOCAL_SOURCE_UNAVAILABLE", "NCM_STARTED_NO_IP_ADAPTER_MATCH", "SCOPED_IPV6_PROBE_NO_VERIFIED_ECHO_NOT_SUPPORT_VERDICT"} {
		if !peerPreparationRetryable(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"PEER_ADAPTER_IDENTITY_CHANGED", "TARGET_CHANGED_DURING_DISCOVERY_REPLY", "APPLICATION_CONNECTION_DECLINED", "PEER_PREPARATION_CANCELLED"} {
		if peerPreparationRetryable(s) {
			t.Fatal(s)
		}
	}
}
