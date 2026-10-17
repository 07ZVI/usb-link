//go:build usblink_local_remote

package connectioninstall

import (
	"fmt"
	"suhang/usbnet/internal/platform/windows/netconfig"
)

type localRemoteFailure struct {
	Stage     string                                `json:"stage,omitempty"`
	Operation string                                `json:"operation,omitempty"`
	HRESULT   uint32                                `json:"hresult,omitempty"`
	Cause     netconfig.ResidentFirewallErrorDetail `json:"cause"`
}

func describeLocalRemoteFailure(err error) *localRemoteFailure {
	if err == nil {
		return nil
	}
	op, hr := netconfig.NativeStepFailureDetails(err)
	return &localRemoteFailure{Stage: netconfig.LocalMaintenanceFailureStage(err), Operation: op, HRESULT: hr, Cause: netconfig.ResidentFirewallErrorDetails(err)}
}

func localRemoteErrorText(err error) string {
	if err == nil {
		return ""
	}
	failure := describeLocalRemoteFailure(err)
	if failure.Operation != "" {
		return fmt.Sprintf("%s [stage=%s operation=%s HRESULT=0x%08X cause=%s]", err.Error(), failure.Stage, failure.Operation, failure.HRESULT, failure.Cause.Code)
	}
	return err.Error()
}

// Preserve typed native classifications across constructor failure without
// exposing provider output, filesystem paths, or ephemeral credentials.
func RemoteInitializationDiagnostics(err error) any {
	return map[string]any{"code": RemoteInitializationCode(err), "failure": describeLocalRemoteFailure(err)}
}
