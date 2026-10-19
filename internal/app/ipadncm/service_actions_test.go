package ipadncm

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"suhang/usbnet/internal/buildinfo"
)

func TestLocalControlFailureKeepsRequestIdentityWithoutClaimingOutcome(t *testing.T) {
	id := strings.Repeat("a", 32)
	for _, action := range []string{"local-usb-update-on", "local-usb-update-off", "photo-isolation-on", "photo-isolation-off", "wpd-trace-on", "wpd-trace-off", "photo-policy-on", "photo-policy-off", "ncm-direct-on", "ncm-direct-off", "amds-hold-on", "amds-hold-off", "mac-mtu-cap-auto", "mac-mtu-cap-9000", "mac-mtu-cap-1500"} {
		event, ok := localControlFailureEvent(action, id)
		if !ok || event.Event != "local-control-result" || event.Action != action || event.RequestID != id || event.Code != "CORE_UI_ACTION_FAILED" {
			t.Fatal(action, event, ok)
		}
		b, err := json.Marshal(event)
		var fields map[string]any
		if err != nil || json.Unmarshal(b, &fields) != nil || len(fields) != 4 {
			t.Fatal("failure must not manufacture saved/enabled state", string(b), err)
		}
	}
	for _, tc := range [][2]string{{"local-usb-update-on", ""}, {"photo-isolation-off", strings.Repeat("z", 32)}, {"local-usb-update-on ", id}, {"settings", id}} {
		if _, ok := localControlFailureEvent(tc[0], tc[1]); ok {
			t.Fatal("unrelated or invalid request produced an acknowledgement", tc)
		}
	}
}

func TestServiceTrustMarkerAdmission(t *testing.T) {
	old := buildinfo.LocalDiagnostics
	t.Cleanup(func() { buildinfo.LocalDiagnostics = old })
	for _, profile := range []string{"true", "false", ""} {
		buildinfo.LocalDiagnostics = profile
		for _, action := range []string{"trust-service-trial-start", "trust-service-trial-cancel"} {
			if serviceAdditionalAction(action) != (profile == "true") {
				t.Fatalf("profile=%q action=%q", profile, action)
			}
		}
		for _, action := range []string{"trust-prompt-first", "trust-prompt-second", "trust-prompt-third", "trust-prompt-first ", "trust-prompt", "trust-service-trial", "trust-service-trial-start "} {
			if serviceAdditionalAction(action) {
				t.Fatalf("unexpected action accepted: %q", action)
			}
		}
	}
	// The installed service must use the tested gate before dispatching to the UI owner.
	source, err := os.ReadFile("service_ui_windows.go")
	if err != nil || !strings.Contains(string(source), "if !serviceAdditionalAction(request.Action)") {
		t.Fatal("service action admission bypassed", err)
	}
}

func TestLocalUSBUpdateActionAdmission(t *testing.T) {
	for _, action := range []string{"local-usb-update-on", "local-usb-update-off"} {
		if serviceAdditionalAction(action) != buildinfo.LocalRemote {
			t.Fatal(action)
		}
	}
	for _, action := range []string{"local-usb-update", "local-usb-update-on ", "local-usb-update-install"} {
		if serviceAdditionalAction(action) {
			t.Fatal(action)
		}
	}
}

func TestLocalTimingTrialActionAdmission(t *testing.T) {
	old := buildinfo.LocalDiagnostics
	t.Cleanup(func() { buildinfo.LocalDiagnostics = old })
	for _, profile := range []string{"true", "false", ""} {
		buildinfo.LocalDiagnostics = profile
		for _, action := range []string{"trust-timing-fast", "trust-timing-delayed", "trust-timing-reset", "photo-isolation-on", "photo-isolation-off", "wpd-trace-on", "wpd-trace-off", "photo-policy-on", "photo-policy-off", "ncm-direct-on", "ncm-direct-off", "amds-hold-on", "amds-hold-off", "mac-mtu-cap-auto", "mac-mtu-cap-9000", "mac-mtu-cap-1500"} {
			if serviceAdditionalAction(action) != (buildinfo.LocalRemote && profile == "true") {
				t.Fatal(profile, action)
			}
		}
		for _, action := range []string{"trust-timing", "trust-timing-fast ", "trust-timing-delay-120", "trust-timing-run", "photo-isolation-on ", "photo-isolation", "photo-isolation-reset"} {
			if serviceAdditionalAction(action) {
				t.Fatal("unknown timing action admitted", action)
			}
		}
	}
}
