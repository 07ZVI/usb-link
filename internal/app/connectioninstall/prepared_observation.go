package connectioninstall

import (
	"fmt"
	"regexp"
	"sync/atomic"
)

// Diagnostic fields never authorize a prepared installation. No account,
// source path, job contents or secret is included in the observation.
type PreparedInstallObservation struct {
	ObservationOnly bool   `json:"observation_only"`
	Version         string `json:"version,omitempty"`
	Phase           string `json:"phase"`
	Code            string `json:"code"`
	NativeError     uint32 `json:"native_error"`
}

type preparedInstallFailure struct {
	observation PreparedInstallObservation
}

func (e *preparedInstallFailure) Error() string {
	return fmt.Sprintf("%s [phase=%s native=%d]", e.observation.Code, e.observation.Phase, e.observation.NativeError)
}

var preparedLastObservation atomic.Pointer[PreparedInstallObservation]
var preparedDiagnosticCode = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,95}$`)
var preparedDiagnosticVersion = regexp.MustCompile(`^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`)

func boundedPreparedObservation(version, phase, code string, native uint32) PreparedInstallObservation {
	if !preparedDiagnosticVersion.MatchString(version) {
		version = ""
	}
	if !preparedDiagnosticCode.MatchString(phase) {
		phase = "UNKNOWN"
	}
	if !preparedDiagnosticCode.MatchString(code) {
		code = "PREPARED_INSTALL_VERIFICATION_FAILED"
	}
	return PreparedInstallObservation{true, version, phase, code, native}
}

func LastPreparedInstallObservation() PreparedInstallObservation {
	if p := preparedLastObservation.Load(); p != nil {
		return *p
	}
	return boundedPreparedObservation("", "NOT_OBSERVED", "NOT_OBSERVED", 0)
}

// Preserve exactly the existing owner/newer/same-source gate, while reporting
// which predicate failed. This does not add a same-source installation route.
func preparedPolicyProblem(next, previous, userSID, ownerSID string, bound, sameSource bool) string {
	if !validPreparedUserSID(userSID) {
		return "PREPARED_INSTALL_USER_IDENTITY_UNPROVEN"
	}
	if bound {
		if userSID != ownerSID {
			return "PREPARED_INSTALL_OWNER_CHANGED"
		}
		if sameSource {
			return "PREPARED_INSTALL_SOURCE_ALREADY_CURRENT"
		}
		if !preparedInstallPolicy(next, previous, userSID, ownerSID, bound, sameSource) {
			return "PREPARED_INSTALL_VERSION_NOT_NEWER"
		}
	}
	return ""
}
