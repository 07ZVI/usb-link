//go:build windows && amd64

package ipadncm

import (
	"testing"
	"time"
)

func TestAuthorizationReadbackCountsTruncatedCodes(t *testing.T) {
	codes := make([]string, 32)
	for i := range codes {
		codes[i] = "USB_STRING_READ_WIN32_31"
	}
	s := Snapshot{ConnectionReadErrorCodes: codes, Devices: []Device{{Errors: codes}}}
	r := authorizationReadback(s, s, 61*time.Millisecond)
	kept, read := len(r.USB.RejectionCodes), len(r.USB.ConnectionReadErrorCodes)
	if kept == 0 || kept >= len(codes) || kept+r.RejectionCodesOmitted != len(codes) || read == 0 || read >= len(codes) || read+r.ReadCodesOmitted != len(codes) {
		t.Fatal("omitted counts do not account for the truncated codes", r)
	}
}

func TestAuthorizationReadbackRootComparisonDoesNotRequireConfiguredLayout(t *testing.T) {
	s := Snapshot{
		Devices: []Device{{PID: "12AB", CurrentConfiguration: 0, USBDescriptorIdentityVerified: true}},
		Nodes:   []Node{{IDPrefix: `USB\VID_05AC&PID_12AB`, instanceID: `USB\VID_05AC&PID_12AB\TEST_ROOT`}},
	}
	r := authorizationReadback(s, s, time.Millisecond)
	if !r.ExactRootPresent || !r.USB.SameRoot || r.NetworkLayoutEligible || r.CurrentConfiguration != 0 {
		t.Fatal("unconfigured root was misreported as a device change", r)
	}
	changed := s
	changed.Nodes = []Node{{IDPrefix: `USB\VID_05AC&PID_12AB`, instanceID: `USB\VID_05AC&PID_12AB\OTHER_ROOT`}}
	if authorizationReadback(s, changed, time.Millisecond).USB.SameRoot {
		t.Fatal("changed root was hidden")
	}
}
