package netconfig

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

func TestMacPairCaptureCoversIndependentResidentAndOwnedDad(t *testing.T) {
	for mask := 0; mask < 16; mask++ {
		if MacLaunchNeedsUSBPair(mask&1 != 0, mask&2 != 0, mask&4 != 0, mask&8 != 0) != (mask != 0) {
			t.Fatalf("capture selection mask %d", mask)
		}
	}
}
func TestMacLaunchFirstFailureCannotBeOverwrittenByCleanup(t *testing.T) {
	var first FirstMacStartupFailure
	b, ok := first.Capture("mac_attached_owner", errors.New("private device identity"))
	if !ok || strings.Contains(string(b), "private") {
		t.Fatal(string(b), ok)
	}
	row, e := DecodeNativeStepFailureMessage(b)
	if e != nil || row.Operation != "mac_attached_owner" || row.Code != "MAC_ATTACHED_OWNER_FAILED" || row.HRESULT != 0 {
		t.Fatal(row, e)
	}
	if _, ok = first.Capture("mac_session_cleanup", errors.New("Close")); ok {
		t.Fatal("cleanup replaced first failure")
	}
	for _, bad := range []string{
		strings.Replace(string(b), `"code":"MAC_ATTACHED_OWNER_FAILED"`, `"code":"MAC_SESSION_CLEANUP_FAILED"`, 1),
		strings.Replace(string(b), `"code":"MAC_ATTACHED_OWNER_FAILED"`, `"code":"private file path"`, 1),
		strings.Replace(string(b), `"code":"MAC_ATTACHED_OWNER_FAILED"`, `"code":null`, 1),
		strings.Replace(string(b), `"code":"MAC_ATTACHED_OWNER_FAILED"`, `"code":"MAC_ATTACHED_OWNER_FAILED","code":"MAC_ATTACHED_OWNER_FAILED"`, 1),
	} {
		if _, e = DecodeNativeStepFailureMessage([]byte(bad)); e == nil {
			t.Fatal("unknown code admitted")
		}
	}
	var provider FirstMacStartupFailure
	b, ok = provider.Capture("mac_resident_batch", errors.Join(&NativeStepFailure{Operation: "firewall_rules", Cause: testCOMFailure(0x80041008)}, errors.New("cleanup")))
	row, e = DecodeNativeStepFailureMessage(b)
	if !ok || e != nil || row.Operation != "firewall_rules" || row.HRESULT != 0x80041008 || row.Code != "" {
		t.Fatal("typed provider cause lost", row, e)
	}
}

func TestMacResidentActualCauseCodeUsesOnlyBoundedCompiledProjection(t *testing.T) {
	for _, c := range []struct {
		e      error
		want   string
		native uint32
	}{
		{fmt.Errorf("private source: %w", errors.New("USB_RESIDENT_STORE_UNPROVEN")), "USB_RESIDENT_STORE_UNPROVEN", 0},
		{fmt.Errorf("private source: %w", errors.New("CORE_BATCH_BINDING_CHANGED")), "CORE_BATCH_BINDING_CHANGED", 0},
		{errors.New("USB_MAC_CURRENT_USB_ATTACHMENT_CHANGED"), "USB_MAC_CURRENT_USB_ATTACHMENT_CHANGED", 0},
		{errors.New("USB_INTERFACE_PROOF_CHANGED"), "USB_INTERFACE_PROOF_CHANGED", 0},
		{errors.New("USB_MAC_RECREATE_INSTALLED_NOT_UNIQUE"), "USB_MAC_RECREATE_INSTALLED_NOT_UNIQUE", 0},
		{errors.New("prefix CORE_BATCH_BINDING_CHANGED suffix"), "USB_RESIDENT_OPERATION_FAILED", 0},
		{fmt.Errorf("private source: %w", syscall.Errno(5)), "USB_RESIDENT_OPERATION_FAILED", 5},
		{errors.New("prefix USB_RESIDENT_STORE_UNPROVEN suffix"), "USB_RESIDENT_OPERATION_FAILED", 0},
	} {
		var first FirstMacStartupFailure
		b, ok := first.Capture("mac_resident_mac_plan", c.e)
		row, e := DecodeNativeStepFailureMessage(b)
		if !ok || e != nil || row.CauseCode != c.want || row.NativeError != c.native || strings.Contains(string(b), "private") {
			t.Fatal(string(b), row, e)
		}
		for _, bad := range []string{
			strings.Replace(string(b), `"cause_code":"`+c.want+`"`, `"cause_code":"private SOURCE"`, 1),
			strings.Replace(string(b), `"cause_code":"`+c.want+`"`, `"cause_code":null`, 1),
			strings.Replace(string(b), `"cause_code":"`+c.want+`"`, `"cause_code":"`+c.want+`","cause_code":"`+c.want+`"`, 1),
			strings.TrimSuffix(string(b), "}") + `,"native_error":4294967296}`,
		} {
			if _, e := DecodeNativeStepFailureMessage([]byte(bad)); e == nil {
				t.Fatal("unsafe cause scalar admitted", bad)
			}
		}
	}
}
