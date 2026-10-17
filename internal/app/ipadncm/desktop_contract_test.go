package ipadncm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"suhang/usbnet/internal/contracts/desktopipc"
	"testing"
)

type desktopContractCase struct {
	name      string
	mac, ipad ApplicationResult
	stopping  bool
}

func desktopContractCases() []desktopContractCase {
	mac := ApplicationResult{DeviceKind: "Mac", Status: "MAC_RUNNING", WindowsIPv4: "10.6.9.1", ServicesReady: true, MacPeerResolved: true, ObservedTransmitMbps: 800, ObservedReceiveMbps: 24, USBSpeed: "SuperSpeed"}
	ipad := ApplicationResult{DeviceKind: "iPad", Status: "USB_APPLICATION_TRIAL_RUNNING", WindowsIPv4: "10.6.9.1", ProposedIPadIPv4: "10.6.9.3", HTTPVerified: true, ObservedTransmitMbps: 160, ObservedReceiveMbps: 8, BenchmarkURL: "http://10.6.9.1:1234/"}
	waiting := ApplicationResult{DeviceKind: "iPad", Status: "MONITOR_WAITING"}
	pending := ipad
	pending.HTTPVerified, pending.DHCPACKs = false, 1
	paused := ipad
	paused.Status, paused.Error = "MONITOR_PAUSED", "failed"
	return []desktopContractCase{
		{"both-connected", mac, ipad, false},
		{"ipad-removed", mac, waiting, false},
		{"ipad-address-pending", mac, pending, false},
		{"ipad-paused", mac, paused, false},
		{"stopping", mac, ipad, true},
	}
}

func desktopContractPayload(tc desktopContractCase) map[string]any {
	devices := []desktopipc.DeviceStatus{}
	for _, r := range []ApplicationResult{tc.mac, tc.ipad} {
		slot := desktopDeviceStatus(r, tc.stopping)
		slot.Detail = ""
		devices = append(devices, slot)
	}
	return map[string]any{"event": "status", "devices": devices}
}

func TestDesktopProducerContract(t *testing.T) {
	path := filepath.Join("..", "..", "contracts", "desktopipc", "testdata", "producer-status.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name    string         `json:"name"`
		Payload map[string]any `json:"payload"`
	}
	if err = json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	cases := desktopContractCases()
	if len(fixtures) != len(cases) {
		t.Fatal("producer fixture count changed")
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(desktopContractPayload(tc))
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err = json.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
			if fixtures[i].Name != tc.name || !reflect.DeepEqual(got, fixtures[i].Payload) {
				t.Fatalf("producer wire output changed: %s", b)
			}
		})
	}
}
