//go:build windows && amd64

package ipadncm

import (
	"testing"
	"time"
)

func TestAuthorizationReadbackCountsBothTruncationStages(t *testing.T) {
	codes := make([]string, 32)
	for i := range codes {
		codes[i] = "USB_STRING_READ_WIN32_31"
	}
	s := Snapshot{ConnectionReadErrorCodes: codes, Devices: []Device{{Errors: codes}}}
	r := authorizationReadback(s, s, 61*time.Millisecond)
	d := sanitizedAuthorizationFailure(usbAuthorizationFailureDiagnostic{Initial: &r})
	if len(d.Initial.USB.RejectionCodes) != 8 || d.Initial.RejectionCodesOmitted != 24 || len(d.Initial.USB.ConnectionReadErrorCodes) != 8 || d.Initial.ReadCodesOmitted != 24 {
		t.Fatal("omitted counts lost the first truncation", d.Initial)
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
