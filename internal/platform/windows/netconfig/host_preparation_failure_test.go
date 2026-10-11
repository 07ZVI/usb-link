package netconfig

import (
	"errors"
	"fmt"
	"testing"
)

func TestHostPreparationFailurePreservesCauseAndRejectsUnknownCode(t *testing.T) {
	cause := errors.New("private provider path")
	failure := &HostPreparationFailure{Code: "USB_HOST_RESIDENT_PREPARE_FAILED", Cause: cause}
	wrapped := fmt.Errorf("outer: %w", failure)
	if !errors.Is(wrapped, cause) || HostPreparationFailureCode(wrapped) != failure.Code {
		t.Fatal("compiled cause lost")
	}
	if failure.Error() != failure.Code {
		t.Fatal("private provider exposed")
	}
	if HostPreparationFailureCode(&HostPreparationFailure{Code: "USB_HOST_PRIVATE_CUSTOM", Cause: cause}) != "" {
		t.Fatal("unknown retained")
	}
}
