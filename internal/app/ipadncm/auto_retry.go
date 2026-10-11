package ipadncm

import "time"

// A bounded recovery budget belongs to one continuously attached device. Device
// notifications alone must never reset it: our own mode changes generate them.
type autoRetryBudget struct{ used int }

func (b *autoRetryBudget) delay(reason string, applicationRan bool) time.Duration {
	if b.used >= 3 {
		return 0
	}
	retryable := reason == "" || (applicationRan && reason == "USB_DISCONNECTED")
	switch reason {
	// A Mac root can arrive before its two WinUSB interfaces. These failures
	// occur before a bridge is started, so retry the same stable attachment
	// within the existing budget; never retry consent or cleanup failures.
	case "MAC_EXACT_PAIR_UNAVAILABLE", "MAC_WINUSB_PAIR_NOT_READY":
		retryable = true
	case "APPLE_USB_DEVICE_NOT_READY", "APPLE_USB_QUERY_CANCELLED_OR_TIMED_OUT",
		"NCM_NOT_ACTIVE_AFTER_MODE_CHECK", "NCM_PRESENT_NO_NATIVE_DRIVER_NODE",
		"NCM_DRIVER_STATE_UNAVAILABLE", "NCM_NATIVE_NODE_NO_PROBLEM_OBSERVED_NOT_NETWORK_PROOF",
		"NEED_ONE_READABLE_APPLE_USB_DEVICE", "USB_TARGET_CHANGED_OR_UNREADABLE",
		"TIME_LIMIT_NO_CHANGE", "REACTIVATION_ROOT_NOT_READY", "EXACT_ROOT_REENUMERATION_TIMEOUT",
		"TARGET_RESTART_TIMEOUT", "NCM_STARTED_NO_IP_ADAPTER_MATCH":
		retryable = true
	}
	if peerPreparationRetryable(reason) {
		retryable = true
	}
	if !retryable {
		return 0
	}
	return []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second}[b.used]
}

// Require a fresh, stable cache reading of the SAME root before each retry.
type sameAttachmentGate struct{ since time.Time }

func (g *sameAttachmentGate) ready(now time.Time, previous string, p idlePresence) bool {
	if !p.readable || !p.candidate || previous == "" || p.identity != previous {
		g.since = time.Time{}
		return false
	}
	if g.since.IsZero() {
		g.since = now
		return false
	}
	return now.Sub(g.since) >= 2*time.Second
}

func peerPreparationRetryable(status string) bool {
	switch status {
	case "PREFERRED_TARGET_IPV6_LINK_LOCAL_SOURCE_UNAVAILABLE", "NCM_STARTED_NO_IP_ADAPTER_MATCH", "SCOPED_IPV6_PROBE_NO_VERIFIED_ECHO_NOT_SUPPORT_VERDICT":
		return true
	}
	return false
}
