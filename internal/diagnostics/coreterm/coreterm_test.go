package coreterm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreviousRunWithoutStopIsReportedUncleanWithCrashOutput(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(release)
	t0 := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	first := Begin(dir, "0.10.19", 100, t0)
	if first.PreviousEnded != "none" || first.Current.State != "running" {
		t.Fatalf("%+v", first)
	}
	// The process dies: a fatal trace was written, and no stop was recorded.
	if err := os.WriteFile(filepath.Join(dir, crashLeaf), []byte("fatal error: concurrent map writes\n\x1b[31mgoroutine 7\n"+strings.Repeat("frame\n", 2000)), 0o600); err != nil {
		t.Fatal(err)
	}
	second := Begin(dir, "0.10.19", 200, t0.Add(time.Hour))
	if second.PreviousEnded != "unclean" || second.Previous == nil || second.Previous.PID != 100 {
		t.Fatalf("%+v", second)
	}
	if !strings.Contains(second.Previous.CrashOutput, "concurrent map writes") || len(second.Previous.CrashOutput) > crashExcerptLimit || strings.Contains(second.Previous.CrashOutput, "\x1b") {
		t.Fatal(second.Previous.CrashOutput)
	}
	if second.LastAbnormal == nil || second.LastAbnormal.Why != "crash_output_present" || second.LastAbnormal.Run.PID != 100 {
		t.Fatalf("%+v", second.LastAbnormal)
	}
	// An orderly stop is recorded, and the abnormal record survives later runs.
	End("SCM_STOP_OR_SHUTDOWN", 0, t0.Add(2*time.Hour))
	third := Begin(dir, "0.10.19", 300, t0.Add(3*time.Hour))
	if third.PreviousEnded != "clean" || third.Previous.StopReason != "SCM_STOP_OR_SHUTDOWN" || third.LastAbnormal == nil || third.LastAbnormal.Run.PID != 100 {
		t.Fatalf("%+v", third)
	}
	End("CORE_SERVICE_LOCAL_IPC_STOPPED: CORE_IPC_LISTENER_FAILED: x", 5, t0.Add(4*time.Hour))
	fourth := Begin(dir, "0.10.19", 400, t0.Add(5*time.Hour))
	if fourth.Previous == nil || fourth.Previous.StopCode != 5 || !strings.HasPrefix(fourth.Previous.StopReason, "CORE_SERVICE_LOCAL_IPC_STOPPED") {
		t.Fatalf("%+v", fourth)
	}
	End("test", 0, t0)
}

func TestDamagedOrRedirectedRecordNeverBlocksStart(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(release)
	if err := os.WriteFile(filepath.Join(dir, runLeaf), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := Begin(dir, "0.10.19", 1, time.Now())
	if s.PersistenceErr == "" || s.Current.State != "running" {
		t.Fatalf("%+v", s)
	}
	End("test", 0, time.Now())
	s = Begin(dir, "0.10.19", 2, time.Now())
	if s.PersistenceErr != "" || s.PreviousEnded != "clean" {
		t.Fatalf("record not repaired: %+v", s)
	}
	End("test", 0, time.Now())
}
