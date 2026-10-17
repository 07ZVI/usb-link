//go:build windows && amd64

package ipadncm

import (
	"encoding/json"
	"os"
	"testing"
)

func initialConfigurationFixture(t *testing.T) Snapshot {
	t.Helper()
	var f struct {
		Before struct{ Configurations []Configuration }
	}
	b, err := os.ReadFile("testdata/observed-mode-layout-0.5.2.json")
	if err != nil || json.Unmarshal(b, &f) != nil {
		t.Fatal("missing measured descriptor fixture")
	}
	serial := "000000000000000000000001"
	return Snapshot{
		Nodes:   []Node{{IDPrefix: `USB\VID_05AC&PID_12AB`, instanceID: `USB\VID_05AC&PID_12AB\` + serial}},
		Devices: []Device{{PID: "12AB", USBProduct: "iPad", USBDescriptorIdentityVerified: true, usbIdentityPortStable: true, Configurations: f.Before.Configurations, hub: "private-test-hub", port: 1, pid: 0x12ab, usbBCDDevice: 0x1316, usbSerial: serial}},
	}
}

func TestInitialConfigurationWaitRequiresCompleteVerifiedZeroSnapshot(t *testing.T) {
	s := initialConfigurationFixture(t)
	if _, ok := initialUSBConfigurationWaitTarget(s); !ok {
		t.Fatal("verified measured cfg0 rejected")
	}
	for _, mutate := range []func(*Snapshot){
		func(s *Snapshot) { s.Error = "QUERY_FAILED" }, func(s *Snapshot) { s.HubErrors = 1 }, func(s *Snapshot) { s.ConnectionReadErrors = 1 },
		func(s *Snapshot) { s.ConnectionReadErrorCodes = []string{"FAILED"} }, func(s *Snapshot) { s.Devices[0].Errors = []string{"FAILED"} },
		func(s *Snapshot) { s.Devices[0].CurrentConfiguration = 3 }, func(s *Snapshot) { s.Devices[0].USBDescriptorIdentityVerified = false },
		func(s *Snapshot) { s.Devices[0].usbIdentityPortStable = false }, func(s *Snapshot) { s.Devices[0].Configurations = nil },
		func(s *Snapshot) { s.Devices = append(s.Devices, s.Devices[0]) }, func(s *Snapshot) { s.Nodes = append(s.Nodes, s.Nodes[0]) },
		func(s *Snapshot) { s.Devices[0].hub = "" }, func(s *Snapshot) { s.Devices[0].port = 0 },
	} {
		s = initialConfigurationFixture(t)
		mutate(&s)
		if _, ok := initialUSBConfigurationWaitTarget(s); ok {
			t.Fatal("incomplete/nonzero snapshot waited")
		}
	}
}
