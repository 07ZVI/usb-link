package bridgeworker

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

// Stop codes are exported on the BRIDGE_STOP log line so the parent and field
// diagnostics can tell a transient data-path failure from an orderly shutdown.
const (
	StopGraceful       = "GRACEFUL"
	StopPanic          = "BRIDGE_PANIC"
	StopUSBInRead      = "USB_IN_READ_FAILED"
	StopUSBInNTB       = "USB_IN_NTB_DECODE_FAILED"
	StopUSBInResubmit  = "USB_IN_RESUBMIT_FAILED"
	StopUSBOutTimeout  = "USB_OUT_COMPLETION_TIMEOUT"
	StopUSBOutWrite    = "USB_OUT_WRITE_FAILED"
	StopWintunSend     = "WINTUN_SEND_FAILED"
	StopOther          = "BRIDGE_ERROR_OTHER"
	ExitCodeFailure    = 1
	ExitCodePanic      = 2
	maxStopDetailBytes = 512
)

// StopCode classifies a worker error. Matching is by the explicit code prefix
// that each fatal data-path site adds; it never changes the error itself.
func StopCode(err error) string {
	if err == nil {
		return StopGraceful
	}
	if errors.Is(err, context.Canceled) {
		return StopGraceful
	}
	text := err.Error()
	for _, code := range []string{StopPanic, StopUSBInRead, StopUSBInNTB, StopUSBInResubmit, StopUSBOutTimeout, StopWintunSend} {
		if strings.Contains(text, code) {
			return code
		}
	}
	if strings.Contains(text, "WinUsb_WritePipe") || strings.Contains(text, "short pipelined write") || strings.Contains(text, "invalid pipelined write") {
		return StopUSBOutWrite
	}
	return StopOther
}

// StopLine is the single machine-readable line logged just before exit.
func StopLine(err error, exitCode int) string {
	detail := ""
	if err != nil {
		detail = err.Error()
		if len(detail) > maxStopDetailBytes {
			detail = detail[:maxStopDetailBytes]
		}
		detail = strings.NewReplacer("\r", " ", "\n", " ").Replace(detail)
	}
	return "BRIDGE_STOP code=" + StopCode(err) + " exit_code=" + strconv.Itoa(exitCode) + " detail=" + detail
}
