package netconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func resetResidentDiagnosticTest() {
	residentFailureState.Lock()
	residentFailureState.values = map[string]ResidentFirewallFailure{}
	residentFailureState.Unlock()
}
func TestResidentHistoryRetainsActualFirstFailureAfterCompletion(t *testing.T) {
	resetResidentDiagnosticTest()
	recordResidentOperation("mac", "prepare", errors.New("USB_RESIDENT_FOREIGN_SCOPE"))
	recordResidentOperation("mac", "finish", errors.New("USB_RESIDENT_RULE_MISSING"))
	recordResidentOperation("mac", "finish", nil)
	got := ResidentFirewallFailureDiagnostics()[1]
	if got.FirstErrorCode != "USB_RESIDENT_FOREIGN_SCOPE" || got.FirstFailurePhase != "prepare" || got.Calls != 3 || got.Failures != 2 || !got.CompletedAfterFailure {
		t.Fatal(got)
	}
	recordResidentOperation("mac", "prepare", nil)
	if ResidentFirewallFailureDiagnostics()[1].FirstErrorCode == "" {
		t.Fatal("later successful preparation erased failure")
	}
}
func TestResidentHistoryPrivacyAndFixedRoleBounds(t *testing.T) {
	resetResidentDiagnosticTest()
	secret := `C:\Users\Someone\private-path GUID HASH SECRET`
	recordResidentOperation("host", "prepare", errors.New(secret))
	recordResidentOperation(secret, "prepare", errors.New(secret))
	recordResidentOperation("ipad", secret, errors.New(secret))
	rows := ResidentFirewallFailureDiagnostics()
	b, _ := json.Marshal(rows)
	if len(rows) != 5 || strings.Contains(string(b), secret) || strings.Contains(string(b), "private-path") || rows[0].FirstErrorCode != "USB_RESIDENT_OPERATION_FAILED" {
		t.Fatal(string(b))
	}
}
func TestResidentHistoryConcurrentCalls(t *testing.T) {
	resetResidentDiagnosticTest()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); recordResidentOperation("host", "prepare", syscall.Errno(5)) }()
	}
	wg.Wait()
	got := ResidentFirewallFailureDiagnostics()[0]
	if got.Calls != 20 || got.Failures != 20 || got.NativeError != 5 {
		t.Fatal(got)
	}
	if residentFailureCode(context.Canceled) != "CANCELLED" || residentFailureCode(context.DeadlineExceeded) != "TIMEOUT" {
		t.Fatal("context projection")
	}
}

func TestResidentErrorAccessorUsesBoundedActualCauses(t *testing.T) {
	v := ResidentFirewallErrorDetails(fmt.Errorf("private SOURCE PATH: %w", errors.New("USB_RESIDENT_LEDGER_CHANGED")))
	if v.Code != "USB_RESIDENT_LEDGER_CHANGED" {
		t.Fatal(v)
	}
	v = ResidentFirewallErrorDetails(errors.New("prefix USB_RESIDENT_LEDGER_CHANGED suffix private path"))
	if v.Code != "USB_RESIDENT_OPERATION_FAILED" {
		t.Fatal(v)
	}
	v = ResidentFirewallErrorDetails(fmt.Errorf("failure: %w", syscall.Errno(5)))
	if v.NativeError != 5 || v.Code != "USB_RESIDENT_OPERATION_FAILED" {
		t.Fatal(v)
	}
}
