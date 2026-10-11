package usbgateway

import (
	"errors"
	"fmt"
)

// WFP returns a DWORD, including on a 64-bit host with a sign-extended return.
type wfpError struct {
	Operation string
	Code      uint32
}

func (e *wfpError) Error() string { return fmt.Sprintf("%s: 0x%08x", e.Operation, e.Code) }
func wfpCallResult(operation string, result uint64) error {
	if code := uint32(result); code != 0 {
		return &wfpError{operation, code}
	}
	return nil
}
func isNotFound(e error) bool {
	var native *wfpError
	return errors.As(e, &native) && (native.Code == 0x80320003 || native.Code == 0x80320007)
}

// A committed policy must pass readback before the caller publishes readiness.
// Keep verification outside the creation transaction.
func commitThenVerify(commit, verify func() error) error {
	if e := commit(); e != nil {
		return e
	}
	return verify()
}
