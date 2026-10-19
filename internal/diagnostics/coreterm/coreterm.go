// Package coreterm keeps a small diagnostic record of how the previous core
// process ended. The service has no automatic restart, so an abnormal end is
// otherwise visible only as a UI that cannot read. Contents are evidence for
// exported diagnostics; they never authorize cleanup or recovery.
package coreterm

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"
)

const runLeaf = "core-run.json"
const crashLeaf = "core-crash.txt"
const fileLimit = 16 << 10
const crashExcerptLimit = 2 << 10
const heartbeat = time.Minute

type Run struct {
	PID         uint32 `json:"pid"`
	Version     string `json:"core_version"`
	StartedUTC  string `json:"started_utc"`
	AliveUTC    string `json:"last_alive_utc"`
	State       string `json:"state"` // running | stopped
	StopReason  string `json:"stop_reason,omitempty"`
	StopCode    uint32 `json:"stop_exit_code,omitempty"`
	StoppedUTC  string `json:"stopped_utc,omitempty"`
	CrashOutput string `json:"crash_output,omitempty"`
	// Startup progress survives without core.log: the last stage reached, the
	// stage that ended startup before acceptance, and why core.log was absent.
	Stage      string `json:"startup_stage,omitempty"`
	StageNote  string `json:"startup_stage_detail,omitempty"`
	FailStage  string `json:"startup_stopped_stage,omitempty"`
	FailDetail string `json:"startup_stopped_detail,omitempty"`
	LogError   string `json:"core_log_error,omitempty"`
	Repair     string `json:"protected_repair,omitempty"`
	Migration  string `json:"folder_migration,omitempty"`
}

type Abnormal struct {
	Run         Run    `json:"run"`
	DetectedUTC string `json:"detected_utc"`
	Why         string `json:"why"`
}

type file struct {
	Current      Run       `json:"current"`
	LastAbnormal *Abnormal `json:"last_abnormal,omitempty"`
	LastStop     *Run      `json:"last_stop,omitempty"`
}

type Status struct {
	Current        Run       `json:"current"`
	Previous       *Run      `json:"previous,omitempty"`
	PreviousEnded  string    `json:"previous_ended,omitempty"` // unclean | clean | none
	LastAbnormal   *Abnormal `json:"last_abnormal,omitempty"`
	CrashOutputOn  bool      `json:"crash_output_enabled"`
	PersistenceErr string    `json:"persistence_error,omitempty"`
}

var state struct {
	sync.Mutex
	dir    string
	data   file
	status Status
	stop   chan struct{}
	crash  *os.File
	early  Run // set before Begin knows the directory
}

func read(dir string) (file, error) {
	var f file
	path := filepath.Join(dir, runLeaf)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > fileLimit {
		return f, errors.New("CORE_RUN_RECORD_UNREADABLE")
	}
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &f) != nil {
		return file{}, errors.New("CORE_RUN_RECORD_INVALID")
	}
	return f, nil
}

func write(dir string, f file) error {
	b, err := json.Marshal(f)
	if err != nil || len(b) > fileLimit {
		return errors.New("CORE_RUN_RECORD_TOO_LARGE")
	}
	path := filepath.Join(dir, runLeaf)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("CORE_RUN_RECORD_REDIRECTED")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func excerpt(dir string) string {
	path := filepath.Join(dir, crashLeaf)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, crashExcerptLimit)
	n, _ := f.Read(buf)
	out := make([]rune, 0, n)
	for _, r := range string(buf[:n]) {
		if r == '\n' || r == '\t' || r >= 0x20 && r < 0x7f {
			out = append(out, r)
		}
	}
	return string(out)
}

// Tail returns the size of the regular file at path and its last limit bytes,
// reduced to printable ASCII. Absent or redirected files report ok=false.
func Tail(path string, limit int64) (size int64, text string, ok bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return 0, "", false
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, "", false
	}
	defer f.Close()
	size = info.Size()
	if size > limit {
		if _, err = f.Seek(size-limit, io.SeekStart); err != nil {
			return size, "", false
		}
	}
	b, _ := io.ReadAll(io.LimitReader(f, limit))
	out := make([]rune, 0, len(b))
	for _, r := range string(b) {
		if r == '\n' || r == '\t' || r >= 0x20 && r < 0x7f {
			out = append(out, r)
		}
	}
	return size, string(out), true
}

// Begin records the start of this core process and classifies how the previous
// one ended: "running" at start means it never recorded a stop. It also routes
// a fatal Go panic or runtime crash to a file in dir, since a service has no
// console for the usual stderr trace.
func Begin(dir, version string, pid uint32, now time.Time) Status {
	state.Lock()
	defer state.Unlock()
	if state.stop != nil {
		close(state.stop)
		state.stop = nil
	}
	utc := now.UTC().Format(time.RFC3339Nano)
	st := Status{PreviousEnded: "none"}
	prior, err := read(dir)
	if err != nil {
		st.PersistenceErr = err.Error()
		prior = file{}
	}
	next := file{LastAbnormal: prior.LastAbnormal, LastStop: prior.LastStop}
	if prior.Current.State != "" {
		previous := prior.Current
		previous.CrashOutput = excerpt(dir)
		st.Previous = &previous
		if previous.State == "running" {
			st.PreviousEnded = "unclean"
			why := "no_stop_recorded"
			if previous.CrashOutput != "" {
				why = "crash_output_present"
			}
			next.LastAbnormal = &Abnormal{Run: previous, DetectedUTC: utc, Why: why}
		} else {
			st.PreviousEnded = "clean"
			stopped := previous
			next.LastStop = &stopped
		}
	}
	if state.crash != nil {
		_ = state.crash.Close()
		state.crash = nil
	}
	// Truncate for this run only after the previous trace was read above.
	if f, err := os.OpenFile(filepath.Join(dir, crashLeaf), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
		if debug.SetCrashOutput(f, debug.CrashOptions{}) == nil {
			state.crash = f
			st.CrashOutputOn = true
		} else {
			_ = f.Close()
		}
	}
	next.Current = Run{PID: pid, Version: version, StartedUTC: utc, AliveUTC: utc, State: "running"}
	e := state.early
	state.early = Run{}
	next.Current.Stage, next.Current.StageNote, next.Current.LogError, next.Current.Repair, next.Current.Migration = e.Stage, e.StageNote, e.LogError, e.Repair, e.Migration
	st.Current = next.Current
	st.LastAbnormal = next.LastAbnormal
	if err := write(dir, next); err != nil && st.PersistenceErr == "" {
		st.PersistenceErr = err.Error()
	}
	state.dir, state.data, state.status = dir, next, st
	stop := make(chan struct{})
	state.stop = stop
	go func() {
		t := time.NewTicker(heartbeat)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case at := <-t.C:
				state.Lock()
				if state.stop == stop {
					state.data.Current.AliveUTC = at.UTC().Format(time.RFC3339Nano)
					_ = write(state.dir, state.data)
				}
				state.Unlock()
			}
		}
	}()
	return st
}

// release stops the heartbeat and closes the crash output so a test's
// temporary directory can be removed; Windows refuses to delete open files.
func release() {
	state.Lock()
	defer state.Unlock()
	if state.stop != nil {
		close(state.stop)
		state.stop = nil
	}
	if state.crash != nil {
		_ = debug.SetCrashOutput(nil, debug.CrashOptions{})
		_ = state.crash.Close()
		state.crash = nil
	}
}

// End marks an orderly or reported stop. A process that never reaches End is
// reported as an unclean end by the next Begin.
func End(reason string, exitCode uint32, now time.Time) {
	state.Lock()
	defer state.Unlock()
	if state.dir == "" || state.data.Current.State != "running" {
		return
	}
	if state.stop != nil {
		close(state.stop)
		state.stop = nil
	}
	utc := now.UTC().Format(time.RFC3339Nano)
	r := &state.data.Current
	r.State, r.StopReason, r.StopCode, r.StoppedUTC, r.AliveUTC = "stopped", boundedASCII(reason, 160), exitCode, utc, utc
	_ = write(state.dir, state.data)
}

func apply(f func(*Run)) {
	if state.dir == "" {
		f(&state.early)
		return
	}
	if state.data.Current.State != "running" {
		return
	}
	f(&state.data.Current)
	_ = write(state.dir, state.data)
}

// Stage records the latest startup step reached; before Begin it is held for
// Begin to adopt.
func Stage(stage, detail string) {
	state.Lock()
	defer state.Unlock()
	apply(func(r *Run) { r.Stage, r.StageNote = boundedASCII(stage, 64), boundedASCII(detail, 240) })
}

// Fail records the stage that ended startup early and the reason.
func Fail(stage, detail string) {
	state.Lock()
	defer state.Unlock()
	apply(func(r *Run) { r.FailStage, r.FailDetail = boundedASCII(stage, 64), boundedASCII(detail, 240) })
}

// LogUnavailable records why core.log could not be opened.
func LogUnavailable(detail string) {
	state.Lock()
	defer state.Unlock()
	apply(func(r *Run) { r.LogError = boundedASCII(detail, 160) })
}

// Migrated records the outcome of the legacy folder migration.
func Migrated(note string) {
	state.Lock()
	defer state.Unlock()
	apply(func(r *Run) { r.Migration = boundedASCII(note, 240) })
}

// Repaired records that protected directories had to be reset before startup.
func Repaired(note string) {
	state.Lock()
	defer state.Unlock()
	apply(func(r *Run) { r.Repair = boundedASCII(note, 240) })
}

func boundedASCII(s string, n int) string {
	out := make([]byte, 0, min(len(s), n))
	for _, r := range s {
		if len(out) >= n {
			break
		}
		if r >= 0x20 && r < 0x7f {
			out = append(out, byte(r))
		} else {
			out = append(out, '?')
		}
	}
	return string(out)
}

// Read returns the current-run record in dir for a reader that is not the
// core (the installer). The same bounded, regular-file-only read applies.
func Read(dir string) (Run, bool) {
	f, err := read(dir)
	return f.Current, err == nil && f.Current.State != ""
}

// Snapshot is the evidence row for exported diagnostics.
func Snapshot() Status {
	state.Lock()
	defer state.Unlock()
	s := state.status
	s.Current = state.data.Current
	return s
}
