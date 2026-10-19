//go:build windows && amd64

package ipadncm

import (
	"context"
	"sync"
)

// Serialize only admission of fixed iPad actions, never USB/service operations.
var ipadActionAdmission sync.Mutex

func signalDiagnosticLoop() {
	select {
	case connectionChanged <- struct{}{}:
	default:
	}
}

// AdmitIPadAttempt stops a newly started iPad attempt when a signed maintenance
// upgrade has been reserved or a network-only request is pending, so the owner
// loop can run that request after cleanup.
func AdmitIPadAttempt(stop context.CancelFunc) {
	ipadActionAdmission.Lock()
	pending := ipadUpgradeReserved.Load() || NetworkOnlyPending()
	ipadActionAdmission.Unlock()
	if pending {
		stop()
	}
}

// A settings error pauses only iPad; the independent Mac management remains.
// Device or settings events wake this wait without adding a polling timer.
func WaitForIPadSettingsRecovery(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-connectionChanged:
		return true
	}
}
