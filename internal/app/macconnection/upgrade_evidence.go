package macconnection

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/diagnostics/exitrecord"
	"suhang/usbnet/internal/diagnostics/logfile"
	"suhang/usbnet/internal/diagnostics/shutdowntrace"
	"time"
)

type connectionEvidenceLogState struct {
	body    string
	written time.Time
}

func programExitEvidenceRow(version, stage string) ([]byte, error) {
	r := exitrecord.Record{Version: version, Exit: exitrecord.Exit{Stage: stage, RecordedUTC: time.Now().UTC().Format(time.RFC3339Nano)}}
	if trace := shutdowntrace.Snapshot(); trace.StartedUTC != "" {
		r.Exit.Trace = &trace
	}
	return exitrecord.Encode(r)
}

// Keep this row independent of the larger bridge evidence and retry failures.
// Refresh at most every 30 seconds so tail readers can recover after an upgrade
// disconnect. The caller uses its existing five-second loop, with no device IO.
func appendChangedConnectionEvidence(dir string, evidence any, previous *connectionEvidenceLogState, now time.Time) error {
	body, err := json.Marshal(evidence)
	if err != nil || string(body) == previous.body && now.Sub(previous.written) < 30*time.Second {
		return err
	}
	if err = appendUpgradeEvidence(dir, body); err != nil {
		return err
	}
	*previous = connectionEvidenceLogState{body: string(body), written: now}
	return nil
}

func appendUpgradeEvidence(dir string, body []byte) error {
	if len(body) > 8192 {
		return fmt.Errorf("upgrade evidence exceeds bound")
	}
	path := filepath.Join(dir, "service.log")
	if st, e := os.Lstat(path); e == nil {
		if !st.Mode().IsRegular() {
			return fmt.Errorf("upgrade evidence path redirected")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	f, e := logfile.Open(path, 128*1024)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = fmt.Fprintf(f, "\nUSB_LINK_UPGRADE_EVIDENCE %s\n", body); e != nil {
		return e
	}
	return f.Sync()
}

// Exit performs bounded IO for only the current runtime. Historical runtime
// count must not multiply syncs; the protected durable leaf is shared by versions.
func recordProgramExitForRuntime(parent, name, version, stage string, save func(string, exitrecord.Record) error, appendRow func(string, []byte) error) error {
	if !exitrecord.RuntimeNameSupported(name) || save == nil || appendRow == nil {
		return fmt.Errorf("EXIT_RECORD_CURRENT_RUNTIME_UNPROVEN")
	}
	dir := filepath.Join(parent, name)
	if !safeRuntimeDirectory(dir) {
		return fmt.Errorf("EXIT_RECORD_CURRENT_RUNTIME_UNPROVEN")
	}
	b, err := programExitEvidenceRow(version, stage)
	if err != nil {
		return err
	}
	r, err := exitrecord.Decode(b)
	if err != nil {
		return err
	}
	writeErr := save(dir, r)
	// Keep persistence failure explicit without a second log flush.
	row := map[string]any{"core_version": r.Version, "program_exit": r.Exit, "program_exit_persistence": map[string]any{"recorded_utc": r.Exit.RecordedUTC, "stage": stage, "verified": writeErr == nil}}
	body, err := json.Marshal(row)
	if err != nil {
		return errors.Join(writeErr, err)
	}
	return errors.Join(writeErr, appendRow(dir, body))
}
