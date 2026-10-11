package netconfig

import "errors"

// NativeStepFailure preserves a real nativeStep failure. The fixed operation
// name and numeric HRESULT are diagnostics only, never mutation authority.
// Error deliberately excludes the underlying provider text or arbitrary paths.
type NativeStepFailure struct {
	Operation string
	Cause     error
}

func (e *NativeStepFailure) Error() string { return "USB_NATIVE_STEP_FAILED" }
func (e *NativeStepFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// NativeStepFailureDetails reads only a typed failure from a fixed native step.
// COM HRESULT text and syscall error text are never parsed.
func NativeStepFailureDetails(err error) (string, uint32) {
	var step *NativeStepFailure
	if !errors.As(err, &step) || step == nil || step.Cause == nil || !NativeOperationValid(step.Operation) {
		return "", 0
	}
	var native interface{ NativeHRESULT() uint32 }
	var hr uint32
	if errors.As(step.Cause, &native) {
		value := native.NativeHRESULT()
		if int32(value) < 0 {
			hr = value
		}
	}
	return step.Operation, hr
}

// HostFailureCodeKnown is the existing candidate receipt's finite vocabulary.
// First-failure memory may not retain a private/custom error merely because it
// begins with USB_HOST_. Adding words requires coordinated reader compatibility.
func HostFailureCodeKnown(code string) bool {
	switch code {
	case "USB_HOST_SOURCE_PIN_FAILED", "USB_HOST_RESIDENT_PREPARE_FAILED", "USB_HOST_RESIDENT_BATCH_FAILED", "USB_HOST_SOURCE_COMPLETE_FAILED", "USB_HOST_NATIVE_STEP_FAILED", "USB_HOST_CLOSE_COMPLETION_PENDING", "USB_HOST_CLOSE_MAPPING_UNPROVEN", "USB_HOST_CLOSE_NODE_CHANGED", "USB_HOST_CLOSE_JOURNAL_CHANGED", "USB_HOST_CLOSE_ADDRESS_OWNERSHIP_UNPROVEN", "USB_HOST_CLOSE_ADDRESS_NOT_ABSENT", "USB_HOST_NATIVE_PNP_BINDING_NOT_UNIQUE", "USB_HOST_NATIVE_NODE_STATE_UNPROVEN", "USB_HOST_NATIVE_OPERATION_FAILED", "USB_HOST_OPERATION_FAILED", "USB_HOST_PREPARED_HEALTH_UNCONFIRMED", "USB_HOST_DRIVER_READBACK_UNCONFIRMED", "USB_HOST_PREPARATION_RETRYING", "USB_HOST_REMOVAL_REBOOT_UNPROVEN", "USB_HOST_RECREATE_ATTEMPT_PENDING", "USB_HOST_RECREATE_TRANSACTION_CHANGED", "USB_HOST_RECREATE_FLAGS_UNPROVEN", "USB_HOST_INTERFACE_CHANGED", "USB_HOST_ADDRESS_OWNERSHIP_CHANGED", "USB_HOST_ADAPTER_ABSENCE_UNCONFIRMED":
		return true
	}
	return false
}

// HostPreparationFailure keeps a compiled stage and the actual cause together.
// It never exports arbitrary source/provider text or grants mutation authority.
type HostPreparationFailure struct {
	Code  string
	Cause error
}

func (e *HostPreparationFailure) Error() string { return e.Code }
func (e *HostPreparationFailure) Unwrap() error { return e.Cause }
func HostPreparationFailureCode(err error) string {
	var v *HostPreparationFailure
	if errors.As(err, &v) && v != nil && HostFailureCodeKnown(v.Code) {
		return v.Code
	}
	return ""
}
