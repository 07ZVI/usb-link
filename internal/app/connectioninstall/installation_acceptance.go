package connectioninstall

import (
	"fmt"
	"strings"
	"time"

	"suhang/usbnet/internal/diagnostics/coreterm"
)

const serviceStoppedState = 1 // svc.Stopped

type coreServiceExit struct {
	State, Win32, Specific uint32
}

// acceptanceDiagnosis states what a failed acceptance wait can safely prove:
// the SCM view of the core and, when it is this release's own record, how its
// startup ended. It is evidence only and never decides recovery.
func acceptanceDiagnosis(exit *coreServiceExit, run *coreterm.Run) string {
	var b strings.Builder
	switch {
	case exit == nil:
		b.WriteString("service_unknown")
	case exit.State == serviceStoppedState:
		fmt.Fprintf(&b, "service_stopped win32=%d exit=%d", exit.Win32, exit.Specific)
	default:
		fmt.Fprintf(&b, "service_state=%d", exit.State)
	}
	if run != nil {
		if run.Stage != "" {
			b.WriteString(" stage=" + run.Stage)
		}
		if run.FailStage != "" {
			b.WriteString(" reason=" + run.FailStage)
			if run.FailDetail != "" {
				b.WriteString(": " + run.FailDetail)
			}
		}
		if run.StopReason != "" {
			b.WriteString(" stop=" + run.StopReason)
		}
		if run.LogError != "" {
			b.WriteString(" core_log=" + run.LogError)
		}
	}
	return b.String()
}

// ownCoreRun accepts a core record only when it is this release's run that
// began no earlier than the wait, so a previous attempt is never blamed.
func ownCoreRun(run coreterm.Run, version string, since time.Time) bool {
	started, err := time.Parse(time.RFC3339Nano, run.StartedUTC)
	return err == nil && run.Version == version && !started.Before(since)
}

// coreEndedBeforeAcceptance is true only for a stopped service whose own run
// record is present: waiting longer cannot make that core accept.
func coreEndedBeforeAcceptance(exit *coreServiceExit, run *coreterm.Run) bool {
	return exit != nil && exit.State == serviceStoppedState && run != nil
}
