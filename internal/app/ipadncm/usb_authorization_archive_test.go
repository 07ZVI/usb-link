//go:build usblink_local_remote

package ipadncm

import (
	"bytes"
	"strings"
	"testing"
)

func TestAuthorizationFailureFitsAutomaticArchive(t *testing.T) {
	code := "USB_" + strings.Repeat("A", 92)
	codes := make([]string, 16)
	for i := range codes {
		codes[i] = code
	}
	shape := usbIdentityStringFailureShape(make([]byte, 255))
	r := &usbAuthorizationReadback{USB: USBDescriptorRecheckDiagnostic{
		Phase: code, InventoryError: code, ProductReadStatus: code, SerialReadStatus: code,
		RejectionCodes: codes, ConnectionReadErrorCodes: codes, OwnOperationCorrelation: code,
		SerialFailureShape: &shape,
	}}
	d := sanitizedAuthorizationFailure(usbAuthorizationFailureDiagnostic{ConsentStatus: code, Initial: r, Latest: r})
	if _, _, err := connectionArchivePayload(d); err != nil {
		t.Fatal("bounded failure summary does not fit automatic export", err)
	}
}

func TestAuthorizationFailureSpecificReasonInArchive(t *testing.T) {
	shape := &USBIdentityStringFailureShape{ReceivedBytes: 82, TerminalNULUnits: 16}
	initial := &usbAuthorizationReadback{USB: USBDescriptorRecheckDiagnostic{
		Phase: "USB_AUTHORIZATION_READBACK", QueryDurationMS: 61,
		DeviceCount: 1, SerialReadStatus: "USB_STRING_READ_WIN32_31",
		SerialFailureShape: shape, RejectionCodes: []string{"USB_SERIAL_OR_PRODUCT_DESCRIPTOR_UNCONFIRMED"},
	}}
	d := sanitizedAuthorizationFailure(usbAuthorizationFailureDiagnostic{
		Attempt: 9, ConsentStatus: "USB_DESCRIPTOR_OR_ATTACHMENT_CHANGED", ReadCount: 2, Initial: initial,
	})
	c := archiveTestController()
	archiveStart(c, 9)
	if !c.record("usb_authorization", d) {
		t.Fatal("failure summary cannot use the automatic archive")
	}
	archiveDrain(c)
	if !bytes.Contains(c.active.body, []byte(`"consent_status":"USB_DESCRIPTOR_OR_ATTACHMENT_CHANGED"`)) || !bytes.Contains(c.active.body, []byte(`"serial_read_status":"USB_STRING_READ_WIN32_31"`)) {
		t.Fatal("specific failure reason missing from automatic export")
	}
}
