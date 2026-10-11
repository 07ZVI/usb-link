package macconnection

import (
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"testing"
)

func TestMacNativeFailureBindsActualLaunchAndRejectsStaleOutput(t *testing.T) {
	epoch := beginNativeFailureAttempt()
	defer beginNativeFailureAttempt()
	binding := nativeChildBinding{pid: 17, creation: 3, nonce: strings.Repeat("a", 24)}
	failure := netconfig.NativeStepDiagnostic{Schema: 1, Operation: "mac_interface", HRESULT: 0x80041008}
	if recordNativeFailure(epoch, binding, failure) {
		t.Fatal("unbound process accepted")
	}
	if !bindNativeFailureChild(epoch, binding) || !recordNativeFailure(epoch, binding, failure) {
		t.Fatal("fixed child evidence lost")
	}
	if NativeStartupFailureDetails()["diagnostic_source"] != "mac_child" {
		t.Fatal("source attribution missing")
	}
	if got, ok := NativeStartupFailure(); !ok || got != failure {
		t.Fatal(got, ok)
	}
	later := netconfig.NativeStepDiagnostic{Schema: 1, Operation: "mac_session_cleanup", Code: "MAC_SESSION_CLEANUP_FAILED"}
	if recordNativeFailure(epoch, binding, later) {
		t.Fatal("cleanup overwrote actual first failure")
	}
	if got, ok := NativeStartupFailure(); !ok || got != failure {
		t.Fatal("first failure changed", got, ok)
	}
	foreign := binding
	foreign.creation++
	if recordNativeFailure(epoch, foreign, failure) {
		t.Fatal("PID reuse accepted")
	}
	next := beginNativeFailureAttempt()
	if recordNativeFailure(epoch, binding, failure) {
		t.Fatal("old attempt output accepted")
	}
	if _, ok := NativeStartupFailure(); ok {
		t.Fatal("old failure attributed to new attempt")
	}
	if !bindNativeFailureChild(next, binding) || !recordNativeFailure(next, binding, failure) {
		t.Fatal("new bound output rejected")
	}
	clearNativeFailure(next)
	if _, ok := NativeStartupFailure(); ok {
		t.Fatal("successful readiness did not clear")
	}
}
func TestMacNativeFailurePrefixCannotComeFromArbitraryErrorText(t *testing.T) {
	payload := `{"schema":1,"operation":"mac_address","hresult":2147749896}`
	line := "2026/10/09 12:34:56.123456 " + netconfig.NativeFailurePrefix + payload
	if _, e := parseNativeFailureLine(line); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{netconfig.NativeFailurePrefix + payload, "2026/10/09 12:34:56.123456 RESULT=STOP error=" + netconfig.NativeFailurePrefix + payload, "2026/10/09 12:34:56.123456 " + netconfig.NativeFailurePrefix + payload + "{}"} {
		if _, e := parseNativeFailureLine(bad); e == nil {
			t.Fatal("unmatched line accepted")
		}
	}
}
