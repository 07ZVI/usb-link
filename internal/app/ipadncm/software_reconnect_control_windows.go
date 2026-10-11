//go:build windows && amd64

package ipadncm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var softwareReconnectOperation sync.Mutex
var softwareReconnectManager struct {
	sync.Mutex
	state                softwareReconnectControlState
	dir                  string
	recoveryVerifiedDir  string
	allowed, queued      *softwareReconnectScope
	scopeCleanupVerified bool
	ctx                  context.Context
	cancel               context.CancelFunc
	kind                 string
	offAfterJob          bool
	offContext           context.Context
	attemptStop          context.CancelFunc
	attemptEpoch         uint64
	upgradeHeld          func() bool
	observations         []SoftwareReconnectOperationObservation
}

type SoftwareReconnectOperationObservation struct {
	Phase    string                             `json:"phase"`
	UTC      string                             `json:"utc"`
	Native   SoftwareReconnectNativeObservation `json:"native"`
	ChangeCR uint32                             `json:"change_cr"`
}
type SoftwareReconnectStatus struct {
	Available                   bool                                    `json:"available"`
	ConsentScopeCleanupVerified bool                                    `json:"captured_consent_session_cleanup_verified"`
	AuthorizedCurrentScope      bool                                    `json:"authorized_current_scope_captured"`
	Pending                     bool                                    `json:"pending"`
	Busy                        bool                                    `json:"busy"`
	RecoveryRequired            bool                                    `json:"recovery_required"`
	Phase                       string                                  `json:"phase"`
	Problem                     string                                  `json:"problem,omitempty"`
	SoftwareAttempts            uint64                                  `json:"software_attempts_not_physical_replugs"`
	Observations                []SoftwareReconnectOperationObservation `json:"recent_native_operations,omitempty"`
}

// Configuration only, default unavailable. Startup must call Recover first;
// this function neither opens a USB device nor implies recovery succeeded.
func InitIPadSoftwareReconnect(dir string, available bool) error {
	ipadActionAdmission.Lock()
	defer ipadActionAdmission.Unlock()
	softwareReconnectManager.Lock()
	defer softwareReconnectManager.Unlock()
	if softwareReconnectManager.state.busy() || softwareReconnectManager.state.blocked {
		return fmt.Errorf("software reconnect recovery/job unresolved")
	}
	if available && (softwareReconnectManager.recoveryVerifiedDir == "" || !strings.EqualFold(filepath.Clean(dir), softwareReconnectManager.recoveryVerifiedDir)) {
		return fmt.Errorf("software reconnect must verify fixed-store startup recovery before enabling")
	}
	softwareReconnectManager.dir, softwareReconnectManager.state.available = dir, available
	return nil
}

// Called only by the connection owner immediately after AllowUSB succeeds.
// The public fixed action accepts no instance IDs, commands, paths or consent.
func CaptureIPadSoftwareReconnectScope(ctx context.Context, a *ConnectionAuthorization) error {
	if a == nil || a.SecurityFailure() != "" {
		return fmt.Errorf("software reconnect requires actual USB consent")
	}
	usbConsentMu.Lock()
	root, allowed := a.grantedRoot, a.Once && a.USBInfoMatched && a.ConsentStatus == "USB_ALLOWED"
	usbConsentMu.Unlock()
	if !allowed || root == "" {
		return fmt.Errorf("software reconnect requires actual USB consent")
	}
	scope, err := captureSoftwareScope(ctx, root)
	if err != nil {
		return err
	}
	softwareReconnectManager.Lock()
	defer softwareReconnectManager.Unlock()
	if softwareReconnectManager.state.busy() {
		return fmt.Errorf("software reconnect scope already frozen by queued action")
	}
	softwareReconnectManager.allowed = &scope
	softwareReconnectManager.scopeCleanupVerified = false
	return nil
}
func ClearIPadSoftwareReconnectScope() {
	softwareReconnectManager.Lock()
	softwareReconnectManager.allowed = nil
	softwareReconnectManager.scopeCleanupVerified = false
	if cancel := softwareReconnectManager.cancel; cancel != nil {
		cancel()
		softwareReconnectManager.state.phase = "authorization_revoked_awaiting_restore"
	}
	softwareReconnectManager.Unlock()
	signalDiagnosticLoop()
}

func RequestIPadSoftwareReconnect(ctx context.Context) error {
	ipadActionAdmission.Lock()
	defer ipadActionAdmission.Unlock()
	if UnpairedExperimentBusy() {
		return fmt.Errorf("unpaired experiment owner active")
	}
	if softwareReconnectUpgradeHeld() {
		return fmt.Errorf("software reconnect unavailable during reserved upgrade")
	}
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("software reconnect canceled before admission")
	}
	if AMDSModeDiagnosticActive() || IPadModeDiagnosticHeld() || IPadCandidateBusy() || NetworkOnlySnapshot().Busy || !IPadCandidateCanConnect() || !NetworkOnlyCanConnect() {
		return fmt.Errorf("iPad action or restoration unresolved")
	}
	if s := connectionMonitor(); s != nil && s.snapshot().Status == "USB_RECOVERY_WAITING" {
		return fmt.Errorf("iPad cleanup unresolved")
	}
	softwareReconnectManager.Lock()
	if !softwareReconnectManager.state.available || softwareReconnectManager.state.busy() || softwareReconnectManager.state.blocked || softwareReconnectManager.allowed == nil {
		softwareReconnectManager.Unlock()
		return fmt.Errorf("software reconnect unavailable, busy or without current consent")
	}
	allowed := *softwareReconnectManager.allowed
	priorCleanupVerified := softwareReconnectManager.scopeCleanupVerified
	softwareReconnectManager.Unlock()
	fresh, err := captureSoftwareScope(ctx, allowed.root)
	if err != nil {
		return err
	}
	if !validSoftwareReconnectRequestScope(allowed, fresh, priorCleanupVerified) {
		return fmt.Errorf("software reconnect authorized USB attachment changed")
	}
	softwareReconnectManager.Lock()
	// Consent replacement can occur while the read-only inventory was running.
	if softwareReconnectManager.allowed == nil || !sameSoftwareReconnectScope(allowed, *softwareReconnectManager.allowed) || !softwareReconnectManager.state.queue() {
		softwareReconnectManager.Unlock()
		return fmt.Errorf("software reconnect scope or admission changed")
	}
	softwareReconnectManager.kind = "reconnect"
	softwareReconnectManager.queued = &fresh
	softwareReconnectManager.ctx, softwareReconnectManager.cancel = context.WithTimeout(ctx, 2*time.Minute)
	softwareReconnectManager.observations = nil
	softwareReconnectManager.Unlock()
	softwareReconnectManager.Lock()
	stop := softwareReconnectManager.attemptStop
	softwareReconnectManager.Unlock()
	time.AfterFunc(200*time.Millisecond, func() {
		if stop != nil {
			stop()
		}
		signalDiagnosticLoop()
	})
	return nil
}

// Owner invokes only after all existing iPad session cleanup has returned and
// its original-value checks succeeded. Never called from the RPC goroutine.
func RunPendingIPadSoftwareReconnect(ctx context.Context, cleanupSafe bool) bool {
	softwareReconnectOperation.Lock()
	defer softwareReconnectOperation.Unlock()
	ipadActionAdmission.Lock()
	if softwareReconnectUpgradeHeld() {
		_ = CancelIdleIPadSoftwareReconnectForUpgrade()
		ipadActionAdmission.Unlock()
		return false
	}
	softwareReconnectManager.Lock()
	if !softwareReconnectManager.state.begin() {
		softwareReconnectManager.Unlock()
		ipadActionAdmission.Unlock()
		return false
	}
	job, cancel, dir, scope, kind, wasBlocked := softwareReconnectManager.ctx, softwareReconnectManager.cancel, softwareReconnectManager.dir, softwareReconnectManager.queued, softwareReconnectManager.kind, softwareReconnectManager.state.blocked
	softwareReconnectManager.recoveryVerifiedDir = ""
	softwareReconnectManager.Unlock()
	ipadActionAdmission.Unlock()
	if cancel != nil {
		defer cancel()
	}
	var result softwareReconnectDraftResult
	var err error
	unresolved := wasBlocked
	if job == nil || !cleanupSafe {
		err = fmt.Errorf("software reconnect requires completed verified session cleanup")
	} else if job.Err() != nil {
		err = job.Err()
	} else if ctx == nil {
		err = fmt.Errorf("software reconnect owner context required")
	} else if ctx.Err() != nil {
		err = ctx.Err()
	} else if kind == "on" || kind == "off" {
		err = recoverSoftwareReconnectStore(dir)
		unresolved = err != nil
	} else if kind != "reconnect" || scope == nil {
		err = fmt.Errorf("invalid fixed software reconnect request")
	} else {
		refreshed, e := refreshSoftwareScopeAfterVerifiedCleanup(job, *scope)
		err = e
		if e == nil {
			store, e := openSoftwareReconnectStore(dir)
			err = e
			if e != nil {
				unresolved = true
			} else {
				_, e = store.Read()
				if !os.IsNotExist(e) {
					unresolved = true
					err = fmt.Errorf("software reconnect preexisting receipt requires explicit recovery")
				} else {
					backend := &softwareReconnectNativeBackend{store: store, scope: refreshed}
					result, err = runSoftwareReconnectDraft(job, backend)
					if store.receipt != 0 {
						unresolved = true
					} else if err != nil {
						_, receiptErr := store.Read()
						unresolved = !os.IsNotExist(receiptErr)
					}
				}
				store.Close()
			}
		}
	}
	problem := ""
	if err != nil {
		problem = err.Error()
	}
	canceled := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || job != nil && job.Err() != nil || ctx != nil && ctx.Err() != nil
	softwareReconnectManager.Lock()
	softwareReconnectManager.state.finish(result, problem, canceled, unresolved || !cleanupSafe)
	softwareReconnectManager.ctx, softwareReconnectManager.cancel, softwareReconnectManager.queued = nil, nil, nil
	softwareReconnectManager.allowed = nil
	softwareReconnectManager.scopeCleanupVerified = false
	if kind == "off" {
		softwareReconnectManager.state.available = false
	}
	if err == nil && !softwareReconnectManager.state.blocked {
		softwareReconnectManager.recoveryVerifiedDir = filepath.Clean(dir)
		if kind == "on" {
			softwareReconnectManager.state.available = true
			softwareReconnectManager.state.phase = "enabled_waiting_for_actual_usb_consent"
		}
		if kind == "off" {
			softwareReconnectManager.state.phase = "disabled_original_root_recovery_verified"
		}
	}
	// Turning off an active action cancels it, then schedules the fixed restore
	// behind its finally. No user-originated setting can skip that obligation.
	if softwareReconnectManager.offAfterJob {
		softwareReconnectManager.offAfterJob = false
		softwareReconnectManager.state.queueSetting(false)
		softwareReconnectManager.kind = "off"
		softwareReconnectManager.ctx, softwareReconnectManager.cancel = context.WithTimeout(softwareReconnectManager.offContext, 2*time.Minute)
		softwareReconnectManager.offContext = nil
	}
	softwareReconnectManager.Unlock()
	signalDiagnosticLoop()
	return true
}

// Fixed ON/OFF requests are consumed by the same connection owner. OFF can
// cancel a running job but never releases its pause before finally restoration.
func RequestIPadSoftwareReconnectSetting(ctx context.Context, enabled bool) error {
	ipadActionAdmission.Lock()
	defer ipadActionAdmission.Unlock()
	if UnpairedExperimentBusy() {
		return fmt.Errorf("unpaired experiment owner active")
	}
	if softwareReconnectUpgradeHeld() {
		return fmt.Errorf("software reconnect unavailable during reserved upgrade")
	}
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("software reconnect setting canceled before admission")
	}
	if AMDSModeDiagnosticActive() || IPadModeDiagnosticHeld() || IPadCandidateBusy() || NetworkOnlySnapshot().Busy {
		return fmt.Errorf("another iPad action active")
	}
	if s := connectionMonitor(); s != nil && s.snapshot().Status == "USB_RECOVERY_WAITING" {
		return fmt.Errorf("iPad session cleanup unresolved")
	}
	softwareReconnectManager.Lock()
	if !enabled {
		softwareReconnectManager.state.available = false
	}
	if !enabled && (softwareReconnectManager.state.pending || softwareReconnectManager.state.running) {
		softwareReconnectManager.offAfterJob, softwareReconnectManager.offContext = true, ctx
		if c := softwareReconnectManager.cancel; c != nil {
			c()
		}
		softwareReconnectManager.state.phase = "turning_off_awaiting_current_finally"
	} else {
		if !softwareReconnectManager.state.queueSetting(enabled) {
			softwareReconnectManager.Unlock()
			return fmt.Errorf("software reconnect setting busy or recovery unresolved")
		}
		softwareReconnectManager.kind = "off"
		if enabled {
			softwareReconnectManager.kind = "on"
		}
		softwareReconnectManager.queued = nil
		softwareReconnectManager.ctx, softwareReconnectManager.cancel = context.WithTimeout(ctx, 2*time.Minute)
	}
	stop := softwareReconnectManager.attemptStop
	softwareReconnectManager.Unlock()
	time.AfterFunc(200*time.Millisecond, func() {
		if stop != nil {
			stop()
		}
		signalDiagnosticLoop()
	})
	return nil
}

func CancelIPadSoftwareReconnect() {
	softwareReconnectManager.Lock()
	if cancel := softwareReconnectManager.cancel; cancel != nil {
		cancel()
		softwareReconnectManager.state.phase = "cancel_requested_awaiting_restore"
	}
	softwareReconnectManager.Unlock()
	signalDiagnosticLoop()
}
func IPadSoftwareReconnectPending() bool {
	softwareReconnectManager.Lock()
	defer softwareReconnectManager.Unlock()
	return softwareReconnectManager.state.pending
}
func IPadSoftwareReconnectBusy() bool {
	softwareReconnectManager.Lock()
	defer softwareReconnectManager.Unlock()
	return softwareReconnectManager.state.busy()
}
func IPadSoftwareReconnectCanConnect() bool {
	softwareReconnectManager.Lock()
	defer softwareReconnectManager.Unlock()
	return softwareReconnectManager.state.canConnect()
}
func IPadSoftwareReconnectSnapshot() SoftwareReconnectStatus {
	softwareReconnectManager.Lock()
	defer softwareReconnectManager.Unlock()
	s := softwareReconnectManager.state
	return SoftwareReconnectStatus{ConsentScopeCleanupVerified: softwareReconnectManager.scopeCleanupVerified, Available: s.available, AuthorizedCurrentScope: softwareReconnectManager.allowed != nil, Pending: s.pending, Busy: s.busy(), RecoveryRequired: s.blocked, Phase: s.phase, Problem: s.problem, SoftwareAttempts: s.softwareAttempts, Observations: append([]SoftwareReconnectOperationObservation(nil), softwareReconnectManager.observations...)}
}
func softwareReconnectPhase(phase string) {
	softwareReconnectManager.Lock()
	softwareReconnectManager.state.phase = phase
	softwareReconnectManager.Unlock()
}
func recordSoftwareNative(phase string, native SoftwareReconnectNativeObservation, cr uint32) {
	softwareReconnectManager.Lock()
	defer softwareReconnectManager.Unlock()
	softwareReconnectManager.state.phase = phase
	softwareReconnectManager.observations = append(softwareReconnectManager.observations, SoftwareReconnectOperationObservation{Phase: phase, UTC: time.Now().UTC().Format(time.RFC3339Nano), Native: native, ChangeCR: cr})
	if len(softwareReconnectManager.observations) > 12 {
		softwareReconnectManager.observations = softwareReconnectManager.observations[len(softwareReconnectManager.observations)-12:]
	}
}

// Shared startup/exit/off/uninstall restoration. Cancellation must first be
// consumed by RunPending; this function refuses an active queued/running job.
// A missing target or foreign state retains the protected receipt and fails.
func RecoverIPadSoftwareReconnect(dir string) (err error) {
	ipadActionAdmission.Lock()
	if AMDSModeDiagnosticActive() || IPadCandidateBusy() || NetworkOnlySnapshot().Busy {
		ipadActionAdmission.Unlock()
		return fmt.Errorf("other iPad action active; wait before software reconnect restoration")
	}
	softwareReconnectManager.Lock()
	if softwareReconnectManager.state.busy() {
		softwareReconnectManager.Unlock()
		ipadActionAdmission.Unlock()
		return fmt.Errorf("cancel/finish software reconnect before restoration")
	}
	softwareReconnectManager.state.recovering = true
	softwareReconnectManager.recoveryVerifiedDir = ""
	softwareReconnectManager.Unlock()
	ipadActionAdmission.Unlock()
	softwareReconnectOperation.Lock()
	defer softwareReconnectOperation.Unlock()
	defer func() {
		softwareReconnectManager.Lock()
		softwareReconnectManager.state.recovering = false
		softwareReconnectManager.state.blocked = err != nil
		softwareReconnectManager.state.problem = ""
		if err != nil {
			softwareReconnectManager.state.problem = err.Error()
			softwareReconnectManager.state.phase = "recovery_required_receipt_retained"
		} else {
			softwareReconnectManager.state.phase = "recovery_verified_no_owned_receipt"
			softwareReconnectManager.recoveryVerifiedDir = filepath.Clean(dir)
		}
		softwareReconnectManager.allowed = nil
		softwareReconnectManager.scopeCleanupVerified = false
		softwareReconnectManager.Unlock()
		signalDiagnosticLoop()
	}()
	return recoverSoftwareReconnectStore(dir)
}

func recoverSoftwareReconnectStore(dir string) error {
	store, err := openSoftwareReconnectStore(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer store.Close()
	j, err := store.Read()
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return recoverSoftwareReconnectDraft(&softwareReconnectNativeBackend{store: store, journal: j}, softwareReconnectReceipt{})
}
