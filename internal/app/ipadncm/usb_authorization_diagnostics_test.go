package ipadncm

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestAuthorizationFailureRetainsBoundedFirstAndLatestEvidence(t *testing.T) {
	shape := &USBIdentityStringFailureShape{ReceivedBytes: 82, TerminalNULUnits: 16}
	initial := &usbAuthorizationReadback{USB: USBDescriptorRecheckDiagnostic{
		Phase: "USB_AUTHORIZATION_READBACK", QueryDurationMS: 61,
		DeviceCount: 1, SerialReadStatus: "USB_STRING_READ_WIN32_31",
		SerialFailureShape: shape, RejectionCodes: []string{"USB_SERIAL_OR_PRODUCT_DESCRIPTOR_UNCONFIRMED"},
	}}
	latest := &usbAuthorizationReadback{ExactRootPresent: false, USB: USBDescriptorRecheckDiagnostic{
		Phase: "USB_AUTHORIZATION_READBACK", DeviceCount: 0,
		ConnectionReadErrors: 1, ConnectionReadErrorCodes: []string{"WIN32_1167"},
	}}
	d := sanitizedAuthorizationFailure(usbAuthorizationFailureDiagnostic{
		Attempt: 9, ConsentStatus: "USB_DESCRIPTOR_OR_ATTACHMENT_CHANGED", ReadCount: 2, Initial: initial, Latest: latest,
	})
	shape.ReceivedBytes = 999
	initial.USB.RejectionCodes[0] = "changed"
	if d.Initial.USB.QueryDurationMS != 61 || d.Initial.USB.SerialFailureShape.ReceivedBytes != 82 || d.Initial.USB.RejectionCodes[0] != "USB_SERIAL_OR_PRODUCT_DESCRIPTOR_UNCONFIRMED" || d.Latest.USB.ConnectionReadErrorCodes[0] != "WIN32_1167" {
		t.Fatal("first or latest failure evidence was lost or aliased", d)
	}
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

func TestAuthorizationFailureRejectsPrivateTextAndBoundsErrors(t *testing.T) {
	private := `USB\VID_05AC&PID_12AB\PRIVATE_DEVICE_SERIAL`
	errors := append([]string{private, "PRIVATE_DEVICE_SERIAL"}, make([]string, 30)...)
	d := sanitizedAuthorizationFailure(usbAuthorizationFailureDiagnostic{
		Phase: private, ConsentStatus: private,
		Initial: &usbAuthorizationReadback{USB: USBDescriptorRecheckDiagnostic{
			InventoryError: private, SerialReadStatus: private, ProductReadStatus: private,
			RejectionCodes: errors, ConnectionReadErrorCodes: errors,
		}},
	})
	b, err := json.Marshal(d)
	if err != nil || strings.Contains(string(b), "PRIVATE_DEVICE_SERIAL") || strings.Contains(string(b), "VID_05AC") || len(d.Initial.USB.RejectionCodes) != 8 || len(d.Initial.USB.ConnectionReadErrorCodes) != 8 || d.Initial.RejectionCodesOmitted != 24 || d.Initial.ReadCodesOmitted != 24 {
		t.Fatal("unbounded or private failure evidence", string(b), err)
	}
	if d.Phase != "authorization_failed" || d.Latest != nil {
		t.Fatal("failure phase or absent-read semantics changed", d)
	}
}

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

func TestAuthorizationFailureRetainsOnlyFixedInitialConfigurationCodes(t *testing.T) {
	for _, code := range []string{"INITIAL_CONFIGURATION_CANCELLED", "INITIAL_CONFIGURATION_TIMEOUT", "INITIAL_CONFIGURATION_TARGET_CHANGED_OR_UNREADABLE", "INITIAL_CONFIGURATION_UNSUPPORTED", "INITIAL_CONFIGURATION_FULL_PROOF_FAILED"} {
		if got := sanitizedAuthorizationFailure(usbAuthorizationFailureDiagnostic{ConsentStatus: code}).ConsentStatus; got != code {
			t.Fatal("fixed wait failure was hidden", code, got)
		}
	}
	if got := sanitizedAuthorizationFailure(usbAuthorizationFailureDiagnostic{ConsentStatus: "INITIAL_CONFIGURATION_PRIVATE_VALUE"}).ConsentStatus; got != "UNKNOWN_OR_UNBOUNDED_REJECTION" {
		t.Fatal("unknown text was exported as a wait failure", got)
	}
}
