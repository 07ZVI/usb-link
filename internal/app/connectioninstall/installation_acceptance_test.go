package connectioninstall

import (
	"testing"
	"time"

	"suhang/usbnet/internal/diagnostics/coreterm"
)

func TestAcceptanceDiagnosisNamesServiceAndStartupReason(t *testing.T) {
	exit := &coreServiceExit{State: serviceStoppedState, Win32: 1066, Specific: 3}
	run := &coreterm.Run{Stage: "mac_recovery", FailStage: "MAC_RECOVERY_UNCONFIRMED", FailDetail: "x", StopReason: "CORE_APPLICATION_STOPPED_BEFORE_CANCELLATION", LogError: "CORE_LOG_PRIVATE_ACL_REQUIRED"}
	want := "service_stopped win32=1066 exit=3 stage=mac_recovery reason=MAC_RECOVERY_UNCONFIRMED: x stop=CORE_APPLICATION_STOPPED_BEFORE_CANCELLATION core_log=CORE_LOG_PRIVATE_ACL_REQUIRED"
	if got := acceptanceDiagnosis(exit, run); got != want {
		t.Fatal(got)
	}
	if got := acceptanceDiagnosis(nil, nil); got != "service_unknown" {
		t.Fatal(got)
	}
	if got := acceptanceDiagnosis(&coreServiceExit{State: 4}, nil); got != "service_state=4" {
		t.Fatal(got)
	}
}

func TestOnlyThisReleasesRecentRunIsBlamed(t *testing.T) {
	since := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	run := coreterm.Run{Version: "0.10.60", StartedUTC: since.Add(time.Second).Format(time.RFC3339Nano)}
	if !ownCoreRun(run, "0.10.60", since) || ownCoreRun(run, "0.10.59", since) || ownCoreRun(run, "0.10.60", since.Add(time.Minute)) {
		t.Fatal("run ownership")
	}
	if ownCoreRun(coreterm.Run{Version: "0.10.60", StartedUTC: "bad"}, "0.10.60", since) {
		t.Fatal("unparseable start accepted")
	}
	stopped := &coreServiceExit{State: serviceStoppedState}
	if !coreEndedBeforeAcceptance(stopped, &run) || coreEndedBeforeAcceptance(stopped, nil) || coreEndedBeforeAcceptance(&coreServiceExit{State: 4}, &run) || coreEndedBeforeAcceptance(nil, &run) {
		t.Fatal("early stop decision")
	}
}
