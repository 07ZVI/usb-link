//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"context"
	"fmt"
	"suhang/usbnet/internal/buildinfo"
	"time"
)

var localConnectionTiming = connectionTimingController{stamp: func(now time.Time) (string, int64) { return trustDiagnostics.stamp(now) }}

func connectionTimingMasterEnabled() bool {
	if !buildinfo.LocalRemote || buildinfo.LocalDiagnostics != "true" || localDeveloperDebug == nil {
		return false
	}
	localDeveloperDebug.mu.Lock()
	defer localDeveloperDebug.mu.Unlock()
	return localDeveloperDebug.state.Enabled
}
func SetConnectionTimingTrial(mode string) error {
	if !validConnectionTimingMode(mode) {
		return fmt.Errorf("CONNECTION_TIMING_MODE_INVALID")
	}
	if mode != "normal" && !connectionTimingMasterEnabled() {
		return fmt.Errorf("CONNECTION_TIMING_LOCAL_DEBUG_REQUIRED")
	}
	return localConnectionTiming.saveSelection(mode, connectionTimingMasterEnabled)
}
func SetConnectionTimingPersistence(save func(string) error, restore func() (string, error)) {
	localConnectionTiming.configurePersistence(save, restore)
}
func RestoreConnectionTimingPreference() error {
	return localConnectionTiming.restoreSelection(connectionTimingMasterEnabled)
}
func ResetConnectionTimingTrial() { localConnectionTiming.resetRuntime() }
func ConnectionTimingDiagnostics() any {
	s := localConnectionTiming.snapshot()
	if run, _ := trustDiagnostics.stamp(time.Now()); run != "" {
		s.RunID = run
	}
	s.Available = buildinfo.LocalRemote && buildinfo.LocalDiagnostics == "true"
	return s
}
func RecordConnectionTimingStage(stage string) { localConnectionTiming.stage(stage) }
func RecordConnectionTimingAttemptStart()      { localConnectionTiming.stage("attempt_started") }
func RecordConnectionTimingNativeRegistration(ok bool) {
	if ok {
		localConnectionTiming.stage("notification_subscribed")
	} else {
		localConnectionTiming.stage("notification_unavailable")
	}
}
func RecordConnectionTimingNativeNotice(code uint32) { localConnectionTiming.nativeNotice(code) }
func connectionTimingWaitPlan() connectionTimingPlan { return localConnectionTiming.plan(time.Now()) }
func connectionTimingWaitBegin()                     { localConnectionTiming.waitBegin() }
func connectionTimingWake(reason string)             { localConnectionTiming.wake(reason) }
func connectionTimingAccept(ctx context.Context, p connectionTimingPlan, kind string, presence idlePresence) (string, idlePresence, bool) {
	return localConnectionTiming.accept(ctx, p, kind, presence, idleUSBPresence, waitConnectionTimingDelay, connectionTimingCandidateAllowed)
}

func connectionTimingOwnerLoop() { localConnectionTiming.ownerLoop() }
