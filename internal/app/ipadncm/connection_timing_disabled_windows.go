//go:build windows && amd64 && !usblink_local_remote

package ipadncm

import (
	"context"
	"fmt"
	"time"
)

func SetConnectionTimingTrial(mode string) error {
	if mode == "normal" {
		return nil
	}
	return fmt.Errorf("CONNECTION_TIMING_LOCAL_DEBUG_REQUIRED")
}
func ResetConnectionTimingTrial()         {}
func connectionTimingMasterEnabled() bool { return false }
func ConnectionTimingDiagnostics() any {
	return nil
}
func RecordConnectionTimingStage(string)            {}
func RecordConnectionTimingAttemptStart()           {}
func RecordConnectionTimingNativeRegistration(bool) {}
func RecordConnectionTimingNativeNotice(uint32)     {}
func connectionTimingWaitPlan() connectionTimingPlan {
	return connectionTimingPlan{mode: "fast", fallback: time.Second}
}
func connectionTimingWaitBegin()  {}
func connectionTimingWake(string) {}
func connectionTimingAccept(ctx context.Context, _ connectionTimingPlan, kind string, p idlePresence) (string, idlePresence, bool) {
	return kind, p, ctx.Err() == nil
}

func connectionTimingOwnerLoop()                    {}
func connectionTimingUSBInterfaceWakeEnabled() bool { return true }

func SetConnectionTimingPersistence(func(string) error, func() (string, error)) {}
func RestoreConnectionTimingPreference() error                                  { return nil }
