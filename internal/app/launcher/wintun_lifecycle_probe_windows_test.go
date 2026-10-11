//go:build windows && amd64

package launcher

import (
	"bytes"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"testing"
)

func TestProbeChildOutputBoundDrainsWithoutGrowing(t *testing.T) {
	var b probeBoundedOutput
	p := bytes.Repeat([]byte{'x'}, 65536)
	for i := 0; i < 3; i++ {
		if n, e := b.Write(p); e != nil || n != len(p) {
			t.Fatal("output was not drained")
		}
	}
	if b.Len() != 32768 || !b.exceeded {
		t.Fatal("output bound not enforced")
	}
}

func TestProbeChildReportRejectsDuplicateUnknownAndTrailingJSON(t *testing.T) {
	for _, raw := range []string{`{"schema":1,"schema":1}`, `{"SCHEMA":1,"schema":1}`, `{"schema":1,"dll_path":"x"}`, `{"schema":1} {"schema":1}`} {
		var v netconfig.WintunLifetimeProbeReport
		if strictCorePayload([]byte(raw), &v) == nil {
			t.Fatal("ambiguous/arbitrary child result accepted")
		}
	}
}

// These tests exercise the real retained process object on Windows. They do
// not create adapters, execute an installed app or authorize any source.
func TestProbeExitedChildUsesRetainedKernelIdentity(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(cmd.Process.Pid)
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		_ = cmd.Wait()
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		_ = cmd.Wait()
		t.Fatal(err)
	}
	creation := probeFiletime(created)
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if exitCode, err := probeExitedChildIdentity(h, pid, creation); err != nil || exitCode != 0 {
		t.Fatalf("same terminated object rejected: exit=%d err=%v", exitCode, err)
	}
	if _, err := probeExitedChildIdentity(h, pid+1, creation); err == nil || err.Error() != "WINTUN_PROBE_CHILD_PID_CHANGED_AFTER_WAIT" {
		t.Fatal("wrong PID accepted", err)
	}
	if _, err := probeExitedChildIdentity(h, pid, creation+1); err == nil || err.Error() != "WINTUN_PROBE_CHILD_CREATION_CHANGED_AFTER_WAIT" {
		t.Fatal("reused PID accepted", err)
	}
}

func TestProbeExitedIdentityRejectsLiveObject(t *testing.T) {
	pid := windows.GetCurrentProcessId()
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		t.Fatal(err)
	}
	if _, err := probeExitedChildIdentity(h, pid, probeFiletime(created)); err == nil || err.Error() != "WINTUN_PROBE_CHILD_TERMINATION_UNPROVEN" {
		t.Fatal("live object accepted", err)
	}
}

func TestProbeTransportFailurePreservesUntrustedChildActions(t *testing.T) {
	v := netconfig.WintunLifetimeProbeReport{Schema: 1, ObservationOnly: true, HoldModule: true, ProcessID: 51, ProcessCreation: 72, PinnedModules: 1, Stage: "closing", Code: "WINTUN_PROBE_CLOSE_ABSENCE_UNCONFIRMED", Rounds: []netconfig.WintunLifetimeProbeRound{{Round: 1, CreateCalled: true, CreateReturned: true, CreatorVerified: true, CloseReturned: true, After: netconfig.WintunLifetimeProbeRead{Complete: true, MIBMatches: 1}}}}
	if err := netconfig.ValidateWintunLifetimeProbeReport(v, true, 51, 72); err != nil {
		t.Fatal(err)
	}
	failed, err := probeTransportFailure(v, "WINTUN_PROBE_CHILD_TIMES_UNREADABLE_AFTER_WAIT")
	if err == nil || failed.TransportError != "WINTUN_PROBE_CHILD_TIMES_UNREADABLE_AFTER_WAIT" || failed.Stage != v.Stage || failed.Code != v.Code || len(failed.Rounds) != 1 || !failed.Rounds[0].CreateCalled || failed.Rounds[0].After.MIBMatches != 1 || failed.PinnedModules != 1 {
		t.Fatal("child actions discarded", failed, err)
	}
	if netconfig.ValidateWintunLifetimeProbeReport(failed, true, 51, 72) == nil {
		t.Fatal("failed transport promoted to an admissible child report")
	}
}
