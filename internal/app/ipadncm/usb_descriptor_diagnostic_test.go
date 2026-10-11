package ipadncm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDescriptorRecheckDiagnosticsBoundedImmutableAndNoPrivateValues(t *testing.T) {
	usbDescriptorRecheckHistory.Lock()
	old := usbDescriptorRecheckHistory.recent
	usbDescriptorRecheckHistory.recent = nil
	usbDescriptorRecheckHistory.Unlock()
	defer func() {
		usbDescriptorRecheckHistory.Lock()
		usbDescriptorRecheckHistory.recent = old
		usbDescriptorRecheckHistory.Unlock()
	}()
	shape := &USBIdentityStringFailureShape{ReceivedBytes: 82, TerminalNULUnits: 16}
	for i := 0; i < 12; i++ {
		recordUSBDescriptorRecheck(USBDescriptorRecheckDiagnostic{Phase: "application_device_event", DeviceCount: i, SerialReadStatus: "USB_STRING_READ_WIN32_31", SerialFailureShape: shape, RejectionCodes: append([]string{`USB\VID_05AC&PID_12AB\SECRET123456789`, "SECRET123456789"}, make([]string, 30)...)})
	}
	shape.ReceivedBytes = 999
	r := USBDescriptorRecheckDiagnostics()
	if len(r) != 8 || r[0].DeviceCount != 4 || len(r[0].RejectionCodes) != 16 || r[0].SerialFailureShape.ReceivedBytes != 82 {
		t.Fatal(r)
	}
	r[0].SerialFailureShape.ReceivedBytes = 1
	r[0].RejectionCodes[0] = "changed"
	if USBDescriptorRecheckDiagnostics()[0].SerialFailureShape.ReceivedBytes != 82 || USBDescriptorRecheckDiagnostics()[0].RejectionCodes[0] == "changed" {
		t.Fatal("history caller can mutate proof")
	}
	b, _ := json.Marshal(USBDescriptorRecheckDiagnostics())
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "VID_05AC") || strings.Contains(string(b), "raw") {
		t.Fatal("private descriptor payload leaked", string(b))
	}
}
