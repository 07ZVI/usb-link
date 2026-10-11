package netconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

func TestFirewallReadFailurePreservesActualFieldAndNumericCause(t *testing.T) {
	err := firewallReadFailure("", "Description", errors.Join(errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_UNKNOWN"), syscall.Errno(5)))
	detail := ResidentFirewallErrorDetails(fmt.Errorf("private source path: %w", err))
	if detail.Field != "MSFT_NetFirewallRule/Description" || detail.Code != "USB_NATIVE_FIREWALL_CONSTRAINT_UNKNOWN" || detail.NativeError != 5 || !errors.Is(err, syscall.Errno(5)) {
		t.Fatal(detail)
	}
	err = firewallReadFailure("MSFT_NetServiceFilter", "_association", syscall.Errno(5))
	detail = ResidentFirewallErrorDetails(err)
	if detail.Field != "MSFT_NetServiceFilter/_association" || detail.Code != "USB_RESIDENT_OPERATION_FAILED" || detail.NativeError != 5 {
		t.Fatal(detail)
	}
	err = firewallReadFailure("MSFT_NetApplicationFilter", "AppPath", errors.Join(errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_UNKNOWN"), nativeReadHRESULTTestError{value: 0x80041002}))
	detail = ResidentFirewallErrorDetails(err)
	if detail.Field != "MSFT_NetApplicationFilter/AppPath" || detail.HRESULT != 0x80041002 || detail.Code != "USB_NATIVE_FIREWALL_CONSTRAINT_UNKNOWN" {
		t.Fatal(detail)
	}
}

func TestFirewallReadFailureFieldsAreCompiledNotProviderValues(t *testing.T) {
	for _, group := range firewallGroups {
		for _, property := range group.fields {
			err := firewallReadFailure(group.class, property, errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_NULL"))
			detail := ResidentFirewallErrorDetails(err)
			if !ValidFirewallConstraintField(detail.Field) || detail.Code != "USB_NATIVE_FIREWALL_CONSTRAINT_NULL" {
				t.Fatal(group, property, detail)
			}
		}
	}
	for _, unknown := range []string{"", "/Description", "MSFT_NetFirewallRule/private-user-path", "MSFT_NetFirewallRule/Description\nSECRET", "MSFT_NetFirewallRule/_association", "unknown/Description"} {
		if ValidFirewallConstraintField(unknown) {
			t.Fatalf("accepted %q", unknown)
		}
	}
	err := firewallReadFailure("SECRET", "PRIVATE", errors.New("SECRET source path"))
	b, _ := json.Marshal(ResidentFirewallErrorDetails(err))
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "PRIVATE") || ResidentFirewallErrorDetails(err).Field != "" {
		t.Fatal(string(b))
	}
}

func TestResidentHistoryKeepsFirstActualConstraintField(t *testing.T) {
	resetResidentDiagnosticTest()
	recordResidentOperation("mac", "prepare", firewallReadFailure("", "RuleGroup", errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_NULL")))
	recordResidentOperation("mac", "finish", firewallReadFailure("MSFT_NetInterfaceFilter", "InterfaceAlias", errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_NULL")))
	recordResidentOperation("mac", "finish", nil)
	got := ResidentFirewallFailureDiagnostics()[1]
	if got.FirstCauseField != "MSFT_NetFirewallRule/RuleGroup" || !got.CompletedAfterFailure {
		t.Fatal(got)
	}
}
