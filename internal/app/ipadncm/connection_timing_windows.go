//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"context"
	"fmt"
	"suhang/usbnet/internal/buildinfo"
	"time"
)

var localConnectionTiming = newAutomaticConnectionTimingController(func(now time.Time) (string, int64) { return trustDiagnostics.stamp(now) })

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
	if mode == "delayed" {
		return fmt.Errorf("CONNECTION_TIMING_DELAY_RETIRED")
	}
	localConnectionTiming.useAutomaticDetection()
	return nil
}

// Older installers may still wire the retired experiment preference. It no
// longer controls ordinary detection or restores a hidden twelve-second delay.
func SetConnectionTimingPersistence(func(string) error, func() (string, error)) {}
func RestoreConnectionTimingPreference() error {
	localConnectionTiming.useAutomaticDetection()
	return nil
}
func ResetConnectionTimingTrial() { localConnectionTiming.useAutomaticDetection() }
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

func connectionTimingUSBInterfaceWakeEnabled() bool {
	return true
}
