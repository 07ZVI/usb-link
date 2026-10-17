// Package exitrecord stores diagnostics only; its contents never authorize cleanup.
package exitrecord

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"suhang/usbnet/internal/diagnostics/shutdowntrace"
	"time"
)

const Limit = 8192
const leaf = "last-program-exit.json"

var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9_-]+)?$`)
var runtimePattern = regexp.MustCompile(`^mac-runtime-([a-f0-9]{64}|[0-9]+\.[0-9]+\.[0-9]+)$`)
var ErrInvalid = errors.New("EXIT_RECORD_INVALID")
var ErrProtection = errors.New("EXIT_RECORD_PROTECTION_UNPROVEN")
var ErrRead = errors.New("EXIT_RECORD_READ_FAILED")
var ErrWrite = errors.New("EXIT_RECORD_WRITE_FAILED")

type Exit struct {
	Stage       string                `json:"stage"`
	RecordedUTC string                `json:"recorded_utc"`
	Trace       *shutdowntrace.Status `json:"cleanup_intervals,omitempty"`
}
type Record struct {
	Version string `json:"core_version"`
	Exit    Exit   `json:"program_exit"`
}

func ValidStage(stage string) bool {
	switch stage {
	case "APPLICATION_JOINED", "APPLICATION_CLEANUP_PENDING", "APPLICATION_CLEANUP_CONFIRMED", "DEFAULT_RESTORE_PENDING", "DEFAULT_RESTORE_CONFIRMED", "RESTORE_FAILED", "RESTORE_READY", "COMMIT_ACKNOWLEDGED":
		return true
	}
	return false
}
func validUTC(s string) bool {
	t, e := time.Parse(time.RFC3339Nano, s)
	return e == nil && t.UTC().Format(time.RFC3339Nano) == s
}
func validate(r Record) error {
	if len(r.Version) > 64 || !versionPattern.MatchString(r.Version) || !ValidStage(r.Exit.Stage) || !validUTC(r.Exit.RecordedUTC) {
		return ErrInvalid
	}
	if r.Exit.Trace != nil && !shutdowntrace.ValidSnapshot(*r.Exit.Trace) {
		return ErrInvalid
	}
	return nil
}
func Encode(r Record) ([]byte, error) {
	if err := validate(r); err != nil {
		return nil, err
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > Limit {
		return nil, ErrInvalid
	}
	return b, nil
}
func Decode(b []byte) (Record, error) {
	var r Record
	if len(b) == 0 || len(b) > Limit {
		return r, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
		return Record{}, ErrInvalid
	}
	canonical, e := Encode(r)
	if e != nil || !bytes.Equal(canonical, b) {
		return Record{}, ErrInvalid
	}
	return r, nil
}

// Projection explicitly separates durable historical evidence from this run's live status.
func Projection(dir string) []byte {
	r, found, e := Read(dir)
	return projection(r, found, e)
}

func projection(r Record, found bool, e error) []byte {
	if !found && e == nil {
		return nil
	}
	if e != nil {
		code := "EXIT_RECORD_READ_FAILED"
		if errors.Is(e, ErrProtection) {
			code = ErrProtection.Error()
		} else if errors.Is(e, ErrInvalid) {
			code = ErrInvalid.Error()
		}
		b, _ := json.Marshal(map[string]any{"last_program_exit": map[string]any{"source": "protected_last_exit_record", "integrity": "unverified", "error": code}})
		return b
	}
	b, _ := json.Marshal(map[string]any{"last_program_exit": map[string]any{"source": "protected_last_exit_record", "integrity": "verified", "current_run": false, "record": r}})
	return b
}

func RuntimeNameSupported(name string) bool { return runtimePattern.MatchString(name) }

// All verified runtime versions share one bounded historical record.
func recordPath(currentRuntime string) string {
	return filepath.Join(filepath.Dir(currentRuntime), leaf)
}
