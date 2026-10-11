package netconfig

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type testCOMFailure uint32

func (e testCOMFailure) Error() string         { return "private COM description" }
func (e testCOMFailure) NativeHRESULT() uint32 { return uint32(e) }

func TestNativeStepFailureRetainsOnlyFixedOperationAndTypedHRESULT(t *testing.T) {
	original := testCOMFailure(0x80041008)
	err := nativeStep(nil, "shared_host_firewall", func() error { return fmt.Errorf("private path: %w", original) })
	var step *NativeStepFailure
	if !errors.As(err, &step) || !errors.Is(err, original) || strings.Contains(err.Error(), "private") {
		t.Fatal("typed wrapping/unwrapping/privacy failed", err)
	}
	op, hr := NativeStepFailureDetails(err)
	if op != "shared_host_firewall" || hr != 0x80041008 {
		t.Fatal(op, hr)
	}
	// A raw HRESULT or a string resembling one is not a real fixed nativeStep.
	for _, cause := range []error{original, errors.New("COM_HRESULT_80041008"), &NativeStepFailure{Operation: "user-controlled-path", Cause: original}, (*NativeStepFailure)(nil)} {
		if op, hr = NativeStepFailureDetails(cause); op != "" || hr != 0 {
			t.Fatal("nonstep evidence exported", op, hr)
		}
	}
	for _, status := range []testCOMFailure{0, 1, 0x7fffffff} {
		err = nativeStep(nil, "firewall_rules", func() error { return status })
		if op, hr = NativeStepFailureDetails(err); op != "firewall_rules" || hr != 0 {
			t.Fatal("successful HRESULT treated as failure", op, hr)
		}
	}
	if nativeStep(nil, "firewall_rules", func() error { return nil }) != nil {
		t.Fatal("successful operation changed")
	}
	if NativeOperationValid("user-controlled-path") || NativeOperationValid("private COM description") {
		t.Fatal("untrusted operation admitted to fixed diagnostic vocabulary")
	}
}
