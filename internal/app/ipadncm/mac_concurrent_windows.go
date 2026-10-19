//go:build windows && amd64

package ipadncm

import (
	"context"
	"fmt"
	"strings"
	"suhang/usbnet/internal/app/macconnection"
	"suhang/usbnet/internal/app/startupopt"
	"suhang/usbnet/internal/app/usbhost"
	"sync/atomic"
	"time"
)

var macForcedRetry atomic.Bool
var recoveryTestControl RecoveryTestControl

func RequestMacRecoveryTest() error { return recoveryTestControl.Request() }

var macRetry = make(chan struct{}, 1)

func requestMacRetry() {
	macForcedRetry.Store(true)
	select {
	case macRetry <- struct{}{}:
	default:
	}
}
func setMacStatus(status, problem string) {
	if s := deviceMonitor("Mac"); s != nil {
		s.update(func(r *ApplicationResult) {
			r.Status = status
			r.Error = problem
			if status == "MONITOR_WAITING" {
				r.ServicesReady = false
				r.ObservedReceiveMbps = 0
				r.ObservedTransmitMbps = 0
			}
		})
	}
}
func waitMac(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-macRetry:
		return true
	case <-timer.C:
		return true
	}
}

// Mac and iPad share the parent lifetime but never an attempt cancellation,
// peer route, authorization object or displayed result. A shared listener
// dispatches to independent, authorized peer handlers.
func RunConcurrentMac(ctx context.Context, parent string, payload, manifest []byte, fatal context.CancelFunc, trace func(macconnection.Result), recovery func(context.Context, string, string) bool) {
	RunConcurrentMacArchive(ctx, parent, macconnection.ArchiveBytes(payload), manifest, fatal, trace, recovery)
}
func RunConcurrentMacArchive(ctx context.Context, parent string, payload macconnection.RuntimeArchive, manifest []byte, fatal context.CancelFunc, trace func(macconnection.Result), recovery func(context.Context, string, string) bool) {
	var lastRoot string
	attempts := 0
	denied := false
	recoveryAttempted := false
	for ctx.Err() == nil {
		if macForcedRetry.Swap(false) {
			attempts, denied = 0, false
			recoveryAttempted = false
		}
		root := macconnection.CurrentRoot()
		if root == "" {
			ids, complete := idlePnPIDs(ctx)
			_, presence := idleUSBPresenceFromIDs(onlyMacIDs(ids), complete)
			if presence.readable && presence.absent {
				lastRoot, attempts, denied = "", 0, false
				recoveryAttempted = false
			}
			setMacStatus("MONITOR_WAITING", "")
			if !waitMac(ctx, time.Second) {
				return
			}
			continue
		}
		if root != lastRoot {
			lastRoot = root
			recoveryAttempted = false
			attempts = 0
			denied = false
		}
		if denied || attempts >= 3 {
			if !denied && !recoveryAttempted && recovery != nil {
				recoveryAttempted = recovery(ctx, root, "Mac network initialization failed after bounded retries")
				if ctx.Err() != nil {
					return
				}
			}
			setMacStatus("MONITOR_PAUSED", "Mac 連線未完成；等待設備重新接入或手動重試。")
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-macRetry:
				timer.Stop()
				attempts = 0
				denied = false
			case <-timer.C:
			}
			continue
		}
		setMacStatus("WAITING_SHARED_HOST", "")
		var waitingRecovery func(context.Context)
		if recovery != nil {
			waitingRecovery = func(raw context.Context) {
				// The callback reports its own transport status. Its bool means only
				// that debugging remains enabled, never that USB/network is ready.
				_ = recovery(raw, root, "WAITING_SHARED_HOST")
			}
		}
		parallel := startupopt.Enabled(startupopt.ParallelPrepare)
		lease := usbhost.NewAttemptLease(ctx, func(join context.Context) (context.Context, func(), bool) {
			if parallel {
				// The bridge now owns USB; raw maintenance cannot run beside it.
				return usbhost.AcquireSharedHost(join)
			}
			return acquireHostWithRecovery(join, usbhost.AcquireSharedHost, waitingRecovery)
		})
		join := func() error {
			// The bridge's gate barrier is 30 seconds. Cancel this same owner
			// sooner if a host never arrives, so its output scanner can join.
			var timer *time.Timer
			if parallel {
				timer = time.AfterFunc(25*time.Second, lease.Cancel)
			}
			if err := lease.Join(); err != nil {
				if timer != nil {
					timer.Stop()
				}
				return err
			}
			if timer != nil && !timer.Stop() {
				return fmt.Errorf("MAC_HOST_JOIN_TIMEOUT")
			}
			RecordSharedHostTiming()
			return nil
		}
		if !parallel {
			if join() != nil {
				lease.Close()
				return
			}
		}
		attempt, cancel := lease.Context(), lease.Cancel
		speedCtx, speedCancel := context.WithTimeout(attempt, 10*time.Second)
		speed, speedError := applicationUSBSpeed(speedCtx, inventoryProduct(speedCtx, 0x1903))
		speedCancel()
		if state := deviceMonitor("Mac"); state != nil {
			state.update(func(r *ApplicationResult) { r.USBSpeed, r.USBSpeedError = speed, speedError })
		}
		auth := &ConnectionAuthorization{}
		auth.BeginSecurityAttempt(attempt, cancel)
		detachTest := recoveryTestControl.Attach(attempt, cancel)
		result := macconnection.RunArchiveWithHostJoin(attempt, parent, payload, manifest, func(current string) bool {
			if attempt.Err() != nil {
				return false
			}
			return auth.AllowUSB("Mac", current, "1903", "ncm-first-pair-0-1-v1", macconnection.CurrentRoot)
		}, UpdateMacMonitor, join)
		detachTest()
		auth.FinishSecurityAttempt()
		hostInvalidated := lease.Invalidated()
		cancel()
		lease.Close()
		UpdateMacMonitor(result)
		if trace != nil {
			trace(result)
		}
		if result.BridgeStarted && !result.CleanupConfirmed {
			setMacStatus("MONITOR_PAUSED", "MAC_CLEANUP_UNCONFIRMED: "+result.Error)
			fatal()
			return
		}
		if ctx.Err() != nil {
			return
		}
		if recoveryTestControl.Consume() && recovery != nil && root == macconnection.CurrentRoot() {
			test, testCancel := context.WithTimeout(ctx, 45*time.Second)
			recovery(test, root, "USB 恢復自檢 · 正常網路暫停，45 秒後自動恢復")
			testCancel()
			attempts, denied, recoveryAttempted = 0, false, false
			if !waitMac(ctx, time.Second) {
				return
			}
			continue
		}
		if hostInvalidated && ctx.Err() == nil {
			attempts = 0
			denied = false
			continue
		}
		denied = strings.Contains(result.Error, "DECLINED") || auth.SecurityFailure() != ""
		if result.Ready && result.CleanupConfirmed {
			attempts = 0
		} else {
			attempts++
		}
		if !waitMac(ctx, time.Duration(max(1, attempts))*5*time.Second) {
			return
		}
	}
}

func MacRecoveryRetryRequested() bool { return macForcedRetry.Load() }

func ConsumeMacRecoveryRetry() bool {
	if !macForcedRetry.Swap(false) {
		return false
	}
	select {
	case <-macRetry:
	default:
	}
	return true
}
