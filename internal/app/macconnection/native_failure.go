package macconnection

import (
	"fmt"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"sync"
	"time"
)

// Private launch binding is derived from the actual fixed command, not a child
// log or RPC. Only diagnostic scalars leave this store; no readiness/permission
// path consults it. A new attempt invalidates delayed output from an older one.
type nativeChildBinding struct {
	pid      uint32
	creation uint64
	nonce    string
}

var macNativeFailure = struct {
	sync.Mutex
	epoch            uint64
	binding          nativeChildBinding
	bridgeSHA256     string
	failure          netconfig.NativeStepDiagnostic
	projection       *netconfig.MacNullProjection
	anchorProjection *netconfig.MacAnchorProjection
	diagnosticTiming *netconfig.BridgeNetworkScriptTiming
	cleanupFailure   *MacCleanupFailureObservation
}{}

func beginNativeFailureAttempt() uint64 {
	macNativeFailure.Lock()
	defer macNativeFailure.Unlock()
	macNativeFailure.epoch++
	macNativeFailure.binding = nativeChildBinding{}
	macNativeFailure.bridgeSHA256 = ""
	macNativeFailure.failure = netconfig.NativeStepDiagnostic{}
	macNativeFailure.projection = nil
	macNativeFailure.anchorProjection = nil
	macNativeFailure.diagnosticTiming = nil
	macNativeFailure.cleanupFailure = nil
	return macNativeFailure.epoch
}
func bindNativeFailureChild(epoch uint64, b nativeChildBinding) bool {
	return bindNativeFailureChildSource(epoch, b, "")
}

// The production caller supplies the compiled hash only after unpackArchive's
// complete manifest/content verification and the actual process capture. This
// is an observation of that launch, never a new permission or liveness proof.
func bindNativeFailureChildSource(epoch uint64, b nativeChildBinding, bridgeSHA256 string) bool {
	macNativeFailure.Lock()
	defer macNativeFailure.Unlock()
	if epoch != macNativeFailure.epoch || b.pid == 0 || b.creation == 0 || len(b.nonce) != 24 || strings.Trim(b.nonce, "0123456789abcdef") != "" || (bridgeSHA256 != "" && !compiledBridgeHash(bridgeSHA256)) {
		return false
	}
	if macNativeFailure.binding.pid != 0 {
		return macNativeFailure.binding == b && macNativeFailure.bridgeSHA256 == bridgeSHA256
	}
	macNativeFailure.binding = b
	macNativeFailure.bridgeSHA256 = bridgeSHA256
	return true
}
func recordNativeFailure(epoch uint64, b nativeChildBinding, v netconfig.NativeStepDiagnostic) bool {
	macNativeFailure.Lock()
	defer macNativeFailure.Unlock()
	if epoch != macNativeFailure.epoch || macNativeFailure.binding != b || b.pid == 0 || !netconfig.NativeStepDiagnosticValid(v) {
		return false
	}
	if netconfig.NativeStepDiagnosticValid(macNativeFailure.failure) {
		return false // A later Close failure cannot replace this attempt's first cause.
	}
	macNativeFailure.failure = v
	return true
}
func clearNativeFailure(epoch uint64) {
	macNativeFailure.Lock()
	defer macNativeFailure.Unlock()
	if epoch == macNativeFailure.epoch {
		macNativeFailure.failure = netconfig.NativeStepDiagnostic{}
		macNativeFailure.projection = nil
		macNativeFailure.anchorProjection = nil
		macNativeFailure.diagnosticTiming = nil
		macNativeFailure.cleanupFailure = nil
	}
}
func NativeStartupFailure() (netconfig.NativeStepDiagnostic, bool) {
	macNativeFailure.Lock()
	defer macNativeFailure.Unlock()
	v := macNativeFailure.failure
	return v, macNativeFailure.binding.pid != 0 && netconfig.NativeStepDiagnosticValid(v)
}

// The binding persists after Ready for a success-event shadow observation, but
// a later attempt invalidates it. This is not a substitute for a live process,
// protected session, current USB and interface checks in the shadow caller.
func nativeFailureSourceBindingCurrent(epoch uint64, b nativeChildBinding) bool {
	macNativeFailure.Lock()
	defer macNativeFailure.Unlock()
	return epoch == macNativeFailure.epoch && b.pid != 0 && b.creation != 0 && macNativeFailure.binding == b && compiledBridgeHash(macNativeFailure.bridgeSHA256)
}

func parseNativeFailureLine(line string) (netconfig.NativeStepDiagnostic, error) {
	// Only the child logger's exact line prefix, never a marker embedded inside
	// an arbitrary error or payload. Parsing date shape does not compare clocks.
	if len(line) <= 27 || len(line) > 1024 || line[26] != ' ' || !strings.HasPrefix(line[27:], netconfig.NativeFailurePrefix) {
		return netconfig.NativeStepDiagnostic{}, fmt.Errorf("MAC_NATIVE_FAILURE_LINE_INVALID")
	}
	if _, e := time.Parse("2006/01/02 15:04:05.000000", line[:26]); e != nil {
		return netconfig.NativeStepDiagnostic{}, fmt.Errorf("MAC_NATIVE_FAILURE_LINE_INVALID")
	}
	return netconfig.DecodeNativeStepFailureMessage([]byte(line[27+len(netconfig.NativeFailurePrefix):]))
}

// Source is exposed separately from the compatible candidate receipt. The
// historical USB_HOST_NATIVE_STEP_FAILED code is reused only as a diagnostic
// classification; this store never contributes to shared-host readiness.
func NativeStartupFailureDetails() map[string]any {
	macNativeFailure.Lock()
	defer macNativeFailure.Unlock()
	v := macNativeFailure.failure
	if macNativeFailure.binding.pid == 0 || !netconfig.NativeStepDiagnosticValid(v) {
		return map[string]any{"diagnostic_source": "unavailable"}
	}
	out := map[string]any{"diagnostic_source": "mac_child", "operation": v.Operation, "hresult": v.HRESULT, "code": v.Code, "cause_code": v.CauseCode, "cause_field": v.CauseField, "native_error": v.NativeError, "firewall_null_projection": netconfig.CopyMacNullProjection(macNativeFailure.projection), "firewall_anchor_projection": netconfig.CopyMacAnchorProjection(macNativeFailure.anchorProjection)}
	if macNativeFailure.diagnosticTiming != nil {
		out["diagnostic_script_timing"] = *macNativeFailure.diagnosticTiming
	}
	if MacCleanupFailureObservationValid(macNativeFailure.cleanupFailure) {
		out["cleanup_failure"] = *macNativeFailure.cleanupFailure
	}
	return out
}

func recordMacNullProjection(epoch uint64, b nativeChildBinding, v *netconfig.MacNullProjection) bool {
	macNativeFailure.Lock()
	defer macNativeFailure.Unlock()
	if epoch != macNativeFailure.epoch || b.pid == 0 || macNativeFailure.binding != b || macNativeFailure.failure.Operation != "mac_resident_mac_plan" || macNativeFailure.failure.CauseCode != "USB_NATIVE_FIREWALL_CONSTRAINT_NULL" || macNativeFailure.projection != nil || !netconfig.MacNullProjectionValid(v) {
		return false
	}
	macNativeFailure.projection = netconfig.CopyMacNullProjection(v)
	return true
}
func recordMacDiagnosticTiming(epoch uint64, b nativeChildBinding, v netconfig.BridgeNetworkScriptTiming) bool {
	macNativeFailure.Lock()
	defer macNativeFailure.Unlock()
	if epoch != macNativeFailure.epoch || b.pid == 0 || macNativeFailure.binding != b || macNativeFailure.failure.Operation != "mac_resident_mac_plan" || (macNativeFailure.failure.CauseCode != "USB_NATIVE_FIREWALL_CONSTRAINT_NULL" && macNativeFailure.failure.CauseCode != "USB_RESIDENT_FOREIGN_SCOPE") || macNativeFailure.diagnosticTiming != nil || v.Operation != "diagnostic" || len(netconfig.CopyBridgeNetworkScriptTimings([]netconfig.BridgeNetworkScriptTiming{v})) != 1 {
		return false
	}
	macNativeFailure.diagnosticTiming = &v
	return true
}
func parseMacNullProjectionLine(line string) (*netconfig.MacNullProjection, error) {
	const loggerPrefix = "owned network configuration: "
	if len(line) <= 27 || len(line) > 8192 || line[26] != ' ' {
		return nil, fmt.Errorf("MAC_NULL_PROJECTION_LINE_INVALID")
	}
	if _, e := time.Parse("2006/01/02 15:04:05.000000", line[:26]); e != nil {
		return nil, e
	}
	body := line[27:]
	if strings.HasPrefix(body, loggerPrefix+netconfig.MacNullProjectionPrefix) {
		body = strings.TrimSuffix(body[len(loggerPrefix):], " error=<nil>")
	}
	if !strings.HasPrefix(body, netconfig.MacNullProjectionPrefix) {
		return nil, fmt.Errorf("MAC_NULL_PROJECTION_LINE_INVALID")
	}
	return netconfig.DecodeMacNullProjection([]byte(body[len(netconfig.MacNullProjectionPrefix):]))
}

func recordMacAnchorProjection(epoch uint64, b nativeChildBinding, v *netconfig.MacAnchorProjection) bool {
	macNativeFailure.Lock()
	defer macNativeFailure.Unlock()
	if epoch != macNativeFailure.epoch || b.pid == 0 || macNativeFailure.binding != b || macNativeFailure.failure.Operation != "mac_resident_mac_plan" || macNativeFailure.failure.CauseCode != "USB_RESIDENT_FOREIGN_SCOPE" || macNativeFailure.anchorProjection != nil || !netconfig.MacAnchorProjectionValid(v) {
		return false
	}
	macNativeFailure.anchorProjection = netconfig.CopyMacAnchorProjection(v)
	return true
}
func parseMacAnchorProjectionLine(line string) (*netconfig.MacAnchorProjection, error) {
	if len(line) <= 27 || len(line) > 36*1024 || line[26] != ' ' || !strings.HasPrefix(line[27:], netconfig.MacAnchorProjectionPrefix) {
		return nil, fmt.Errorf("MAC_ANCHOR_PROJECTION_LINE_INVALID")
	}
	if _, e := time.Parse("2006/01/02 15:04:05.000000", line[:26]); e != nil {
		return nil, e
	}
	return netconfig.DecodeMacAnchorProjection([]byte(line[27+len(netconfig.MacAnchorProjectionPrefix):]))
}
