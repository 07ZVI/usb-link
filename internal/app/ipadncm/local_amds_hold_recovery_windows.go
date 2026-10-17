//go:build windows && amd64

package ipadncm

import (
	"context"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

var localAMDSHoldReserved atomic.Bool

func amdsHoldConfigHash(c mgr.Config) (string, error) {
	return amdsHoldPortableConfigHash(amdsHoldPortableConfig(c))
}
func amdsHoldPortableConfig(c mgr.Config) localAMDSHoldConfig {
	return localAMDSHoldConfig{c.BinaryPathName, c.ServiceStartName, c.ServiceType, c.StartType, c.SidType, c.Dependencies, c.DelayedAutoStart}
}
func openAMDSHoldService() (m *mgr.Mgr, s *mgr.Service, err error) {
	m, e := mgr.Connect()
	if e != nil {
		return nil, nil, amdsHoldError("AMDS_HOLD_SCM_UNAVAILABLE", amdsHoldNativeCode(e))
	}
	s, e = m.OpenService(localAMDSHoldService)
	if e != nil {
		m.Disconnect()
		return nil, nil, amdsHoldError("AMDS_HOLD_SERVICE_UNAVAILABLE", amdsHoldNativeCode(e))
	}
	return m, s, nil
}
func amdsHoldReadback(s *mgr.Service, j localAMDSHoldJournal) (svc.Status, error) {
	cfg, e := s.Config()
	if e != nil {
		return svc.Status{}, amdsHoldError("AMDS_HOLD_CONFIG_UNREADABLE", amdsHoldNativeCode(e))
	}
	hash, e := amdsHoldConfigHash(cfg)
	if e != nil {
		return svc.Status{}, e
	}
	if hash != j.ConfigHash || cfg.StartType != j.StartType {
		return svc.Status{}, amdsHoldError("AMDS_HOLD_CONFIG_CHANGED", 0)
	}
	state, e := s.Query()
	if e != nil {
		return svc.Status{}, amdsHoldError("AMDS_HOLD_STATE_UNREADABLE", amdsHoldNativeCode(e))
	}
	return state, nil
}

func amdsHoldTransition(s *mgr.Service, j localAMDSHoldJournal, wanted svc.State, allowed func() bool) (localAMDSHoldObservation, error) {
	read := func() (localAMDSHoldObservation, error) {
		cfg, e := s.Config()
		if e != nil {
			return localAMDSHoldObservation{}, amdsHoldError("AMDS_HOLD_CONFIG_UNREADABLE", amdsHoldNativeCode(e))
		}
		hash, e := amdsHoldConfigHash(cfg)
		if e != nil {
			return localAMDSHoldObservation{}, e
		}
		status, e := s.Query()
		if e != nil {
			return localAMDSHoldObservation{}, amdsHoldError("AMDS_HOLD_STATE_UNREADABLE", amdsHoldNativeCode(e))
		}
		return localAMDSHoldObservation{uint32(status.State), cfg.StartType, hash}, nil
	}
	change := func(state uint32) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e := diagnosticServiceState(ctx, s, svc.State(state)); e != nil {
			return amdsHoldError("AMDS_HOLD_STATE_CHANGE_FAILED", amdsHoldNativeCode(e))
		}
		return nil
	}
	return localAMDSHoldTransition(j, uint32(wanted), read, change, allowed)
}
func restoreLocalAMDSHoldLocked(dir string) error {
	j, e := readLocalAMDSHoldJournal(dir)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return amdsHoldError("AMDS_HOLD_JOURNAL_UNPROVEN", amdsHoldNativeCode(e))
	}
	if j.Restored {
		return nil
	}
	localAMDSHoldReserved.Store(true)
	if _, e = readAMDSDiagnosticReceipt(filepath.Join(dir, "amds-diagnostic.json")); !os.IsNotExist(e) {
		return amdsHoldError("AMDS_HOLD_LEGACY_RECOVERY_PENDING", 0)
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
	if _, e = amdsHoldTransition(s, j, svc.State(j.OriginalState), nil); e != nil {
		return e
	}
	j.Restored = true
	return writeLocalAMDSHoldJournal(dir, j)
}
func RestoreLocalAMDSHold(dir string) error {
	lease, e := openLocalAMDSHoldLease(dir)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(lease)
	e = restoreLocalAMDSHoldLocked(dir)
	if e == nil {
		localAMDSHoldReserved.Store(false)
	}
	return e
}
