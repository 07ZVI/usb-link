package connectioninstall

import "errors"

type remoteInitializationError struct {
	stage string
	cause error
}

func (e *remoteInitializationError) Error() string { return RemoteInitializationCode(e) }
func (e *remoteInitializationError) Unwrap() error { return e.cause }

func remoteInitializationFailure(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	return &remoteInitializationError{stage: stage, cause: cause}
}

// Publish fixed classifications, never provider strings or protected paths.
func RemoteInitializationCode(err error) string {
	if err == nil {
		return ""
	}
	var failure *remoteInitializationError
	if errors.As(err, &failure) {
		switch failure.stage {
		case "root":
			return "LOCAL_REMOTE_INITIALIZATION_ROOT_FAILED"
		case "config_read":
			return "LOCAL_REMOTE_INITIALIZATION_CONFIG_READ_FAILED"
		case "config_clear":
			return "LOCAL_REMOTE_INITIALIZATION_CONFIG_CLEAR_FAILED"
		case "consent_clear":
			return "LOCAL_REMOTE_INITIALIZATION_CONSENT_CLEAR_FAILED"
		case "guard":
			return "LOCAL_REMOTE_INITIALIZATION_GUARD_FAILED"
		case "local_firewall":
			return "LOCAL_REMOTE_INITIALIZATION_LOCAL_FIREWALL_FAILED"
		case "legacy_firewall":
			return "LOCAL_REMOTE_INITIALIZATION_LEGACY_FIREWALL_FAILED"
		}
	}
	return "LOCAL_REMOTE_INITIALIZATION_FAILED"
}
