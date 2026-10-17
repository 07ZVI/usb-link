//go:build usblink_local_remote

package connectioninstall

import (
	"encoding/json"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"testing"
)

func TestLocalRemoteInitializationEvidenceKeepsTypedCauseAndFitsBound(t *testing.T) {
	err := remoteInitializationFailure("local_firewall", &netconfig.NativeStepFailure{Operation: "firewall_rules", Cause: localRemoteTestHRESULT{}})
	body, marshalError := json.Marshal(RemoteInitializationDiagnostics(err))
	if marshalError != nil || len(body) > 1024 || strings.Contains(string(body), "private-provider-details") || !strings.Contains(string(body), "LOCAL_REMOTE_INITIALIZATION_LOCAL_FIREWALL_FAILED") || !strings.Contains(string(body), "firewall_rules") {
		t.Fatal(string(body), marshalError)
	}
	if failure := describeLocalRemoteFailure(err); failure.HRESULT != 0x80041008 {
		t.Fatal("constructor wrapper lost real HRESULT", failure)
	}
}

type localRemoteTestHRESULT struct{}

func (localRemoteTestHRESULT) Error() string         { return "private-provider-details" }
func (localRemoteTestHRESULT) NativeHRESULT() uint32 { return 0x80041008 }

func TestLocalRemoteFailurePreservesOperationAndHRESULT(t *testing.T) {
	err := &netconfig.NativeStepFailure{Operation: "firewall_rules", Cause: localRemoteTestHRESULT{}}
	failure := describeLocalRemoteFailure(err)
	if failure.Operation != "firewall_rules" || failure.HRESULT != 0x80041008 {
		t.Fatal(failure)
	}
	message := localRemoteErrorText(err)
	if !strings.Contains(message, "firewall_rules") || !strings.Contains(message, "0x80041008") || strings.Contains(message, "private-provider-details") {
		t.Fatal(message)
	}
}
