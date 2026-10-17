package exitrecord

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/diagnostics/shutdowntrace"
	"testing"
)

func fixture() Record {
	return Record{Version: "0.10.52", Exit: Exit{Stage: "COMMIT_ACKNOWLEDGED", RecordedUTC: "2026-10-18T01:45:45Z", Trace: &shutdowntrace.Status{StartedUTC: "2026-10-18T01:45:28Z", Intervals: []shutdowntrace.Interval{{Phase: shutdowntrace.PhaseMacRecoveryRules, BeginMS: 2957, ElapsedMS: 10962, Complete: true}}}}}
}
func TestRecordRoundTripAndTruncation(t *testing.T) {
	r := fixture()
	b, e := Encode(r)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Decode(b)
	if e != nil || got.Exit.Trace.Intervals[0] != r.Exit.Trace.Intervals[0] {
		t.Fatalf("round trip: %v", e)
	}
	for n := 0; n < len(b); n++ {
		if _, e = Decode(b[:n]); e == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	for _, bad := range [][]byte{append(append([]byte(nil), b...), b...), append(b, ' '), []byte(strings.Replace(string(b), `"core_version":`, `"unknown":"path", "core_version":`, 1)), []byte(strings.Replace(string(b), `"core_version":`, `"core_version":"0.1.0", "core_version":`, 1))} {
		if _, e = Decode(bad); e == nil {
			t.Fatal("noncanonical/unknown accepted")
		}
	}
}
func TestRecordRejectsUnknownAndSensitiveFields(t *testing.T) {
	cases := []func(*Record){func(r *Record) { r.Version = "C:\\private" }, func(r *Record) { r.Exit.Stage = "arbitrary" }, func(r *Record) { r.Exit.RecordedUTC = "not a date" }, func(r *Record) { r.Exit.Trace.StartedUTC = "" }, func(r *Record) { r.Exit.Trace.Intervals[0].Phase = "private path" }, func(r *Record) { r.Exit.Trace.Intervals[0].BeginMS = -1 }, func(r *Record) { r.Exit.Trace.Intervals[0].ElapsedMS = -1 }, func(r *Record) { r.Exit.Trace.Intervals = make([]shutdowntrace.Interval, 33) }}
	for i, change := range cases {
		r := fixture()
		change(&r)
		if _, e := Encode(r); e == nil {
			t.Fatalf("accepted %d", i)
		}
	}
}
func TestRecordBoundAndIndependentSnapshots(t *testing.T) {
	r := fixture()
	r.Exit.Trace.Intervals = nil
	for i := 0; i < 32; i++ {
		r.Exit.Trace.Intervals = append(r.Exit.Trace.Intervals, shutdowntrace.Interval{Phase: shutdowntrace.PhaseDefaultIsolationStop, BeginMS: 9223372036854775807, ElapsedMS: 9223372036854775807, Complete: true})
	}
	r.Exit.Trace.Omitted = ^uint64(0)
	b, e := Encode(r)
	if e != nil || len(b) > Limit {
		t.Fatalf("bound %d: %v", len(b), e)
	}
	a, e := Decode(b)
	if e != nil {
		t.Fatal(e)
	}
	c, _ := Decode(b)
	a.Exit.Trace.Intervals[0].BeginMS = 0
	if c.Exit.Trace.Intervals[0].BeginMS == 0 {
		t.Fatal("aliased")
	}
	wire, _ := json.Marshal(map[string]any{"last_program_exit": map[string]any{"source": "protected_last_exit_record", "integrity": "verified", "current_run": false, "record": r}})
	if len(wire) > 8192 {
		t.Fatalf("wire overflow %d", len(wire))
	}
	if bytes.Contains(wire, []byte("token")) {
		t.Fatal("unexpected identity")
	}
	t.Logf("max record=%d projection=%d", len(b), len(wire))
}
func TestRecordRuntimeScope(t *testing.T) {
	for _, s := range []string{"mac-runtime-0.10.52", "mac-runtime-" + strings.Repeat("a", 64)} {
		if !RuntimeNameSupported(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"mac-runtime-v1", "../mac-runtime-0.10.52", "mac-runtime-0.10.52/tmp", "other"} {
		if RuntimeNameSupported(s) {
			t.Fatal(s)
		}
	}
}

func TestProjectionNeverTreatsHistoryOrReadFailureAsLiveSuccess(t *testing.T) {
	if b := projection(Record{}, false, nil); b != nil {
		t.Fatal("missing record invented")
	}
	b := projection(fixture(), true, nil)
	if !bytes.Contains(b, []byte(`"current_run":false`)) || !bytes.Contains(b, []byte(`"core_version":"0.10.52"`)) || bytes.Contains(b, []byte(`"current_run":true`)) {
		t.Fatal("historical provenance missing")
	}
	for _, e := range []error{ErrInvalid, ErrProtection, errors.New("C:\\private-secret")} {
		b := projection(fixture(), true, e)
		if bytes.Contains(b, []byte("private-secret")) || bytes.Contains(b, []byte("COMMIT_ACKNOWLEDGED")) || !bytes.Contains(b, []byte(`"integrity":"unverified"`)) {
			t.Fatal("failure hidden or leaked")
		}
	}
}

func TestAllRuntimeVersionsUseOneHistoricalLeaf(t *testing.T) {
	parent := t.TempDir()
	a := recordPath(filepath.Join(parent, "mac-runtime-0.10.52"))
	b := recordPath(filepath.Join(parent, "mac-runtime-"+strings.Repeat("a", 64)))
	if a != b || a != filepath.Join(parent, leaf) {
		t.Fatal("historical record follows runtime version")
	}
}
