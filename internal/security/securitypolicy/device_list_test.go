package securitypolicy

import (
	"reflect"
	"testing"
)

func TestDeviceTypesExposeCompositeNetworkAndKeyboardInsteadOfBrandGuess(t *testing.T) {
	nodes := []DeviceNode{{Service: "usbccgp"}, {ClassGUID: "{4d36e972-e325-11ce-bfc1-08002be10318}"}, {ClassGUID: KeyboardClass}, {CompatibleIDs: []string{`USB\Class_03&SubClass_01`}}}
	want := []AccessoryKind{KindComposite, KindKeyboard, KindHID, KindNetwork}
	if got := ClassifyFunctions(nodes); !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	if got := ClassifyFunctions([]DeviceNode{{Service: "UASPStor"}}); !reflect.DeepEqual(got, []AccessoryKind{KindStorage}) {
		t.Fatal(got)
	}
	if got := ClassifyFunctions([]DeviceNode{{Service: "UnknownVendor"}}); !reflect.DeepEqual(got, []AccessoryKind{KindUnknown}) {
		t.Fatal(got)
	}
}

func TestTypesDoNotOverclaimGenericImagingMediaOrCustomUSB(t *testing.T) {
	for _, c := range []struct {
		guid string
		kind AccessoryKind
	}{
		{"{6bdd1fc6-810f-11d0-bec7-08002be2092f}", KindImaging},
		{"{4d36e96c-e325-11ce-bfc1-08002be10318}", KindMedia},
		{"{88bae032-5a81-49f0-bc3d-a4ff138216d6}", KindUnknown},
	} {
		if got := ClassifyFunctions([]DeviceNode{{ClassGUID: c.guid}}); !reflect.DeepEqual(got, []AccessoryKind{c.kind}) {
			t.Fatal(c, got)
		}
	}
}

func TestRevokeCannotDisableLastWorkingInput(t *testing.T) {
	r := RevocationReadiness{CompleteInventory: true, AffectsInput: true, RecoveryVerified: true, ExecutorSupportsRevocation: true}
	if r.CanRevoke() {
		t.Fatal("last input path can be disabled")
	}
	r.OtherVerifiedInputPath = true
	if !r.CanRevoke() {
		t.Fatal("alternate input path ignored")
	}
	r.ExecutorSupportsRevocation = false
	if r.CanRevoke() {
		t.Fatal("unsupported revocation claimed")
	}
}

func TestExplicitDenyOverridesExistingAndRememberedPermissions(t *testing.T) {
	v := AccessoryObservation{Complete: true, ExternalUSB: true, ExistingAtActivation: true, Accepted: true, AttachmentApproved: true, Denied: true}
	if d := (AccessoryPolicy{Enabled: true}).Decide(v); d.Permit || d.Code != "USB_DEVICE_PERMISSION_REVOKED" {
		t.Fatal(d)
	}
}
