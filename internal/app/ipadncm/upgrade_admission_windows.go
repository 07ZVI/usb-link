//go:build windows && amd64

package ipadncm

import (
	"fmt"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/app/remoteupdate"
	"sync"
	"sync/atomic"
)

var ipadUpgradeReserved atomic.Bool

func init() {
	SetIPadSoftwareReconnectUpgradeGuard(IPadUpgradeReservationHeld)
	connectioninstall.RegisterIPadUpgradeAdmission(reserveIPadUpgrade)
	connectioninstall.RegisterRemoteUSBHealth(RemoteUSBConnectionHealthy)
}
func reserveIPadUpgrade() (func(), error) {
	ipadActionAdmission.Lock()
	defer ipadActionAdmission.Unlock()
	if UnpairedExperimentBusy() {
		return nil, fmt.Errorf("unpaired experiment or recovery owns iPad; finish before upgrade")
	}
	amdsDiagnosticJob.Lock()
	defer amdsDiagnosticJob.Unlock()
	ipadCandidateControl.Lock()
	defer ipadCandidateControl.Unlock()
	networkOnly.Lock()
	defer networkOnly.Unlock()
	if IPadSoftwareReconnectExecuting() {
		return nil, fmt.Errorf("iPad software reconnect is executing; wait for verified restoration")
	}
	c, n, ok := remoteupdate.ReserveIdleActions(ipadCandidateControl.pending, ipadCandidateControl.busy, networkOnly.pending, networkOnly.busy, amdsDiagnosticJob.Running, ipadUpgradeReserved.Load())
	if !ok {
		return nil, fmt.Errorf("active iPad action or upgrade reservation; finish before upgrade")
	}
	if err := CancelIdleIPadSoftwareReconnectForUpgrade(); err != nil {
		return nil, err
	}
	// Only requests not yet consumed are cancelled. Applied stage, choices,
	// blocked recovery state and all durable recovery receipts are untouched.
	if c {
		ipadCandidateControl.pending = false
		ipadCandidateControl.problem = "Queued candidate request cancelled for signed maintenance upgrade"
	}
	if n {
		networkOnly.pending = false
		networkOnly.status = "QUEUED_REQUEST_CANCELLED_FOR_UPGRADE"
	}
	ipadUpgradeReserved.Store(true)
	signalDiagnosticLoop()
	var once sync.Once
	return func() {
		once.Do(func() {
			ipadActionAdmission.Lock()
			ipadUpgradeReserved.Store(false)
			ipadActionAdmission.Unlock()
			signalDiagnosticLoop()
		})
	}, nil
}

// IPadUpgradeReservationHeld is a no-I/O guard for additional iPad action
// controllers. Their enqueue/consume must also participate in the main owner
// admission lock; this predicate alone is not an atomic reservation.
func IPadUpgradeReservationHeld() bool { return ipadUpgradeReserved.Load() }
