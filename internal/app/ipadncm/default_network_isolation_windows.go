//go:build windows && amd64

package ipadncm

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

var defaultIsolationStart sync.Once
var defaultIsolationReady atomic.Bool
var defaultIsolation struct {
	sync.Mutex
	lifecycle *defaultIsolationLifecycle
}

func StartDefaultNetworkIsolation(ctx context.Context, dir string) func() {
	defaultIsolationStart.Do(func() {
		var stopPhoto, stopAMDS func()
		c := &defaultIsolationLifecycle{
			policy: func() error { return RestoreLocalPhotoPolicy(dir) },
			photo:  func() error { return RestorePhotoIsolation(dir) },
			amds:   func() error { return RestoreLocalAMDSHold(dir) },
		}
		c.activate = func() {
			// Workers have a private lifetime so shutdown can first revoke all
			// admissions, then join and read back both independent restorations.
			localPhoto.runtimeAllowed = func() bool { return !c.revoked.Load() && ctx.Err() == nil }
			localAMDSHold.runtimeAllowed = func() bool { return !c.revoked.Load() && ctx.Err() == nil }
			stopPhoto = StartPhotoIsolation(context.Background(), dir)
			stopAMDS = StartLocalAMDSHold(context.Background(), dir)
			defaultIsolationReady.Store(true)
			localPhoto.runtimeDefault(true)
			localAMDSHold.runtimeDefault(true)
		}
		c.quiesce = func() {
			defaultIsolationReady.Store(false)
			localPhoto.runtimeDefault(false)
			localAMDSHold.runtimeDefault(false)
			if stopPhoto != nil {
				stopPhoto()
			}
			if stopAMDS != nil {
				stopAMDS()
			}
		}
		defaultIsolation.Lock()
		defaultIsolation.lifecycle = c
		defaultIsolation.Unlock()
		if ctx.Err() == nil {
			_ = c.start()
		}
	})
	return func() { _ = StopDefaultNetworkIsolation() }
}

// Call after network-session cleanup and before dismissing the exit UI. A
// failure is retained in diagnostics and can be retried without reactivation.
func StopDefaultNetworkIsolation() error {
	defaultIsolationReady.Store(false)
	defaultIsolation.Lock()
	c := defaultIsolation.lifecycle
	defaultIsolation.Unlock()
	if c == nil {
		return errors.New("NETWORK_ISOLATION_NOT_INITIALIZED")
	}
	return c.stop()
}

func DefaultNetworkIsolationDiagnostics() any {
	defaultIsolation.Lock()
	c := defaultIsolation.lifecycle
	defaultIsolation.Unlock()
	if c == nil {
		return defaultNetworkIsolationStatus{Phase: "not_started"}
	}
	s := c.snapshot()
	p, a := localPhoto.snapshot(), localAMDSHold.snapshot()
	s.PhotoEffective, s.AMDSEffective = p.Effective, a.Effective
	if s.Phase == "running" && (p.Error != "" || a.Error != "") {
		s.Phase, s.Error = "running_with_error", "NETWORK_ISOLATION_OPERATION_FAILED"
	}
	return s
}

func defaultIsolationAdmission() error {
	defaultIsolation.Lock()
	c := defaultIsolation.lifecycle
	defaultIsolation.Unlock()
	if !defaultIsolationReady.Load() || c == nil || c.revoked.Load() {
		return errors.New("NETWORK_ISOLATION_NOT_READY")
	}
	return nil
}

func defaultPhotoPolicyDiagnostics() any {
	defaultIsolation.Lock()
	c := defaultIsolation.lifecycle
	defaultIsolation.Unlock()
	phase, problem := "retired_runtime_isolation", ""
	if c != nil && !c.snapshot().PolicyRestored {
		phase, problem = "recovery_pending", "PHOTO_POLICY_RESTORE_PENDING"
	}
	return map[string]any{"available": false, "requested": false, "effective": false, "phase": phase, "error": problem, "retained_on_exit": false}
}
