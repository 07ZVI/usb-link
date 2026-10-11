//go:build windows && amd64

package ipadncm

import (
	"fmt"
	"time"
)

// Arm a batch before physical attachment. This action never opens or changes a
// USB device or Apple service, and can be accepted with no iPad attached.
func HoldIPadModeDiagnostics() error {
	ipadActionAdmission.Lock()
	defer ipadActionAdmission.Unlock()
	if UnpairedExperimentBusy() {
		return fmt.Errorf("unpaired experiment owner active")
	}
	if ipadUpgradeReserved.Load() {
		return fmt.Errorf("signed maintenance upgrade reserved")
	}
	if IPadSoftwareReconnectAdmissionBusy() || !IPadSoftwareReconnectCanConnect() {
		return fmt.Errorf("software reconnect or its restoration unresolved")
	}
	if AMDSModeDiagnosticActive() || IPadCandidateBusy() || IPadCandidateSnapshot().Stage != 0 || NetworkOnlySnapshot().Busy {
		return fmt.Errorf("iPad action or candidate already active")
	}
	if !IPadCandidateCanConnect() || !NetworkOnlyCanConnect() {
		return fmt.Errorf("iPad restoration unresolved")
	}
	if s := connectionMonitor(); s != nil && s.snapshot().Status == "USB_RECOVERY_WAITING" {
		return fmt.Errorf("iPad cleanup unresolved")
	}
	amdsDiagnosticBatch.hold()
	amdsDiagnosticJob.Lock()
	stop := amdsDiagnosticJob.AttemptStop
	amdsDiagnosticJob.Unlock()
	time.AfterFunc(200*time.Millisecond, func() {
		if stop != nil {
			stop()
		}
		signalDiagnosticLoop()
	})
	return nil
}

// Only the owner may supply verified=true after completed recovery, or after
// a safe stage-3 transition has proven both mode switches on this exact iPad.
// Cancellation merely requests job termination; it must not call this helper
// until all recovery checks succeed. An active job always refuses release.
func ReleaseIPadModeDiagnosticHoldAfterRecovery(verified bool) bool {
	ipadActionAdmission.Lock()
	defer ipadActionAdmission.Unlock()
	if !amdsDiagnosticBatch.release(verified, AMDSModeDiagnosticActive()) {
		return false
	}
	signalDiagnosticLoop()
	return true
}
