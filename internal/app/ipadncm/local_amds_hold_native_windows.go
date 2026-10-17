//go:build windows && amd64

package ipadncm

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"os"
	"path/filepath"
)

type localAMDSHoldNative struct {
	dir      string
	lease    windows.Handle
	journal  localAMDSHoldJournal
	allowed  func() bool
	identity *localAMDSHoldIdentity
}

func LocalAMDSHoldBusy() bool { return localAMDSHoldReserved.Load() }
func (b *localAMDSHoldNative) recover() error {
	if b.lease != 0 {
		return b.stop()
	}
	return RestoreLocalAMDSHold(b.dir)
}
func (b *localAMDSHoldNative) start(allowed func() bool) error {
	if !allowed() {
		return amdsHoldError("AMDS_HOLD_REQUEST_CANCELLED", 0)
	}
	ipadActionAdmission.Lock()
	amdsDiagnosticJob.Lock()
	busy := amdsDiagnosticJob.Running || amdsDiagnosticJob.Pending
	amdsDiagnosticJob.Unlock()
	if busy || NetworkOnlyAvailable() || NetworkOnlySnapshot().Busy || IPadCandidateBusy() || IPadCandidateSnapshot().Stage != 0 || UnpairedExperimentBusy() {
		ipadActionAdmission.Unlock()
		return amdsHoldError("AMDS_HOLD_OTHER_TRIAL_ACTIVE", 0)
	}
	localAMDSHoldReserved.Store(true)
	ipadActionAdmission.Unlock()
	lease, e := openLocalAMDSHoldLease(b.dir)
	if e != nil {
		localAMDSHoldReserved.Store(false)
		return e
	}
	b.lease = lease
	if _, e = readAMDSDiagnosticReceipt(filepath.Join(b.dir, "amds-diagnostic.json")); !os.IsNotExist(e) {
		return amdsHoldError("AMDS_HOLD_LEGACY_RECOVERY_PENDING", 0)
	}
	if e = restoreLocalAMDSHoldLocked(b.dir); e != nil {
		return e
	}
	if !amdsDiagnosticMu.TryLock() {
		return amdsHoldError("AMDS_HOLD_OTHER_TRIAL_ACTIVE", 0)
	}
	defer amdsDiagnosticMu.Unlock()
	m, s, e := openAMDSHoldService()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	defer s.Close()
	cfg, e := s.Config()
	if e != nil {
		return amdsHoldError("AMDS_HOLD_CONFIG_UNREADABLE", amdsHoldNativeCode(e))
	}
	hash, e := amdsHoldConfigHash(cfg)
	if e != nil {
		return e
	}
	b.identity, _ = amdsHoldConfigIdentity(amdsHoldPortableConfig(cfg))
	status, e := s.Query()
	if e != nil {
		return amdsHoldError("AMDS_HOLD_STATE_UNREADABLE", amdsHoldNativeCode(e))
	}
	if status.State != svc.Running && status.State != svc.Stopped {
		return amdsHoldError("AMDS_HOLD_TRANSITION_PENDING", 0)
	}
	if cfg.StartType == 4 && status.State == svc.Running {
		return amdsHoldError("AMDS_HOLD_ORIGINAL_NOT_RESTORABLE", 0)
	}
	j := localAMDSHoldJournal{Schema: 1, Service: localAMDSHoldService, OriginalState: uint32(status.State), StartType: cfg.StartType, ConfigHash: hash}
	if !allowed() {
		return amdsHoldError("AMDS_HOLD_REQUEST_CANCELLED", 0)
	}
	if e = writeLocalAMDSHoldJournal(b.dir, j); e != nil {
		return e
	}
	b.journal = j
	b.allowed = allowed
	fresh, e := amdsHoldReadback(s, j)
	if e != nil {
		return e
	}
	if fresh.State != status.State {
		return amdsHoldError("AMDS_HOLD_STATE_CHANGED", 0)
	}
	if !allowed() {
		return amdsHoldError("AMDS_HOLD_REQUEST_CANCELLED", 0)
	}
	_, e = amdsHoldTransition(s, j, svc.Stopped, allowed)
	return e
}
func (b *localAMDSHoldNative) stop() error {
	if b.lease == 0 {
		return b.recover()
	}
	e := restoreLocalAMDSHoldLocked(b.dir)
	windows.CloseHandle(b.lease)
	b.lease = 0
	if e == nil {
		localAMDSHoldReserved.Store(false)
	}
	return e
}
func (b *localAMDSHoldNative) sample() (localAMDSHoldSample, error) {
	sample := localAMDSHoldSample{Identity: b.identity, OriginalState: b.journal.OriginalState, StartType: b.journal.StartType}
	if !amdsDiagnosticMu.TryLock() {
		return sample, amdsHoldError("AMDS_HOLD_OTHER_TRIAL_ACTIVE", 0)
	}
	defer amdsDiagnosticMu.Unlock()
	m, s, e := openAMDSHoldService()
	if e != nil {
		return sample, e
	}
	defer m.Disconnect()
	defer s.Close()
	current, e := readLocalAMDSHoldJournal(b.dir)
	if e != nil || current != b.journal {
		return sample, amdsHoldError("AMDS_HOLD_JOURNAL_CHANGED", 0)
	}
	// Service recovery may restart AMDS. The saved, still-current hold intent
	// can stop it again without changing the original restoration obligation.
	if b.allowed == nil {
		return sample, amdsHoldError("AMDS_HOLD_REQUEST_CANCELLED", 0)
	}
	status, e := amdsHoldTransition(s, b.journal, svc.Stopped, b.allowed)
	if e != nil {
		return sample, e
	}
	sample.ServiceState = status.State
	return sample, nil
}
