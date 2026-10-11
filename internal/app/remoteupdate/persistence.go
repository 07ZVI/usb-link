package remoteupdate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// This typed error is issued only after a guarded owner retains its exact job
// and durable obligations. An ordinary failed upload must not capture an API
// slot or gain the experiment's recovery controls.
type retainedJobError struct{ cause error }

func (e *retainedJobError) Error() string {
	return "owned job retained for persistence recovery: " + e.cause.Error()
}
func (e *retainedJobError) Unwrap() error { return e.cause }
func RetainJobError(err error) error {
	if err == nil {
		return nil
	}
	return &retainedJobError{cause: err}
}
func IsRetainedJobError(err error) bool { var e *retainedJobError; return errors.As(err, &e) }

// A receipt with no worker PID does not establish an idle launch boundary.
// The live owner must positively report that native creation was never tried.
func IdleTerminationRetryAllowed(current, owner JobIdentity, statuses []string, launchAttempted, committed bool) bool {
	if launchAttempted || committed || !current.Guarded || !owner.Guarded || current.ID != owner.ID || current.PID != owner.PID || current.Creation != owner.Creation || current.Executable != owner.Executable || !JobIdentityValid(current) || !JobIdentityValid(owner) {
		return false
	}
	for _, status := range statuses {
		if current.Status == status {
			return true
		}
	}
	return false
}

type GuardControl struct {
	Kind    string `json:"kind"`
	Seconds int    `json:"seconds"`
	Nonce   string `json:"nonce"`
}

// Persistence recovery never delegates an arbitrary performance command. It
// reuses only the three bounded guard commands and existing nonce contract.
func DecodeGuardControl(body io.Reader, query string) (GuardControl, error) {
	var q GuardControl
	d := json.NewDecoder(body)
	d.DisallowUnknownFields()
	var extra any
	if query != "" || d.Decode(&q) != nil || d.Decode(&extra) != io.EOF || len(q.Nonce) != 32 || strings.Trim(q.Nonce, "0123456789abcdef") != "" {
		return q, fmt.Errorf("fixed upgrade guard control required")
	}
	if q.Kind == "UPGRADEGUARDON" && q.Seconds == 900 || (q.Kind == "UPGRADEGUARDOFF" || q.Kind == "UPGRADEGUARDSTATE") && q.Seconds == 0 {
		return q, nil
	}
	return q, fmt.Errorf("fixed upgrade guard control required")
}
