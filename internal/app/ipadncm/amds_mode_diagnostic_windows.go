//go:build windows && amd64

package ipadncm

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/buildinfo"
	"sync"
	"time"
)

type AMDSModeDiagnostic struct {
	RequestedState           string  `json:"requested_amds_state"`
	Before                   uint32  `json:"service_state_before"`
	During                   uint32  `json:"service_state_during"`
	After                    uint32  `json:"service_state_after"`
	OriginalStartType        uint32  `json:"original_start_type"`
	ElapsedMS                int64   `json:"elapsed_ms"`
	Restored                 bool    `json:"original_service_state_and_start_type_restored"`
	Mode                     *Result `json:"mode,omitempty"`
	Error                    string  `json:"error,omitempty"`
	RestoreError             string  `json:"restore_error,omitempty"`
	CancelledBeforeChange    bool    `json:"cancelled_before_service_change_no_receipt,omitempty"`
	NoServiceChangeNoReceipt bool    `json:"no_service_change_no_recovery_receipt,omitempty"`
}

var amdsDiagnosticMu sync.Mutex

var amdsDiagnosticJob struct {
	sync.Mutex
	Running           bool
	Pending           bool
	StartedUTC        string
	Phase             string
	Requested         string
	TargetRoot        string
	Result            *AMDSModeDiagnostic
	AttemptStop       context.CancelFunc
	AttemptGeneration uint64
	JobContext        context.Context
	JobCancel         context.CancelFunc
	LocalTrustTrial   bool
	AttemptBefore     uint64
	AttemptAfter      uint64
	TrialObservation  LocalTrustServiceTrial
}

type AMDSModeDiagnosticJob struct {
	Running                    bool                `json:"running"`
	StartedUTC                 string              `json:"started_utc,omitempty"`
	Phase                      string              `json:"phase"`
	Result                     *AMDSModeDiagnostic `json:"result,omitempty"`
	OrdinaryIPadConnectionHeld bool                `json:"ordinary_ipad_connection_held"`
}

func AttachAMDSDiagnosticAttempt(stop context.CancelFunc) func() {
	ipadActionAdmission.Lock()
	amdsDiagnosticJob.Lock()
	amdsDiagnosticJob.AttemptGeneration++
	generation := amdsDiagnosticJob.AttemptGeneration
	amdsDiagnosticJob.AttemptStop = stop
	pending := ipadUpgradeReserved.Load() || amdsDiagnosticJob.Pending || NetworkOnlyPending() || IPadCandidatePending() || IPadModeDiagnosticHeld()
	amdsDiagnosticJob.Unlock()
	ipadActionAdmission.Unlock()
	if pending {
		stop()
	}
	return func() {
		amdsDiagnosticJob.Lock()
		if amdsDiagnosticJob.AttemptGeneration == generation {
			amdsDiagnosticJob.AttemptStop = nil
		}
		amdsDiagnosticJob.Unlock()
	}
}

// Only enqueue and stop the current iPad attempt. Main runs the diagnostic
// after that attempt's grouping and address cleanup; the Mac is independent.
func StartAMDSModeDiagnostic(ctx context.Context, version, requested string) error {
	return startAMDSModeDiagnostic(ctx, version, requested, false)
}

// Fixed local action; ordinary/public builds cannot control the service here.
func StartLocalTrustServiceTrial(ctx context.Context, version string) error {
	if buildinfo.LocalDiagnostics != "true" {
		return fmt.Errorf("LOCAL_DIAGNOSTICS_REQUIRED")
	}
	return startAMDSModeDiagnostic(ctx, version, "stopped", true)
}

func startAMDSModeDiagnostic(ctx context.Context, version, requested string, localTrial bool) error {
	ipadActionAdmission.Lock()
	defer ipadActionAdmission.Unlock()
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("DIAGNOSTIC_CONTEXT_CANCELLED")
	}
	if LocalAMDSHoldBusy() {
		return fmt.Errorf("AMDS_HOLD_ACTIVE_OR_RECOVERY_PENDING")
	}
	if localTrial && (IPadModeDiagnosticHeld() || !IPadCandidateCanConnect() || !NetworkOnlyCanConnect()) {
		return fmt.Errorf("IPAD_DIAGNOSTIC_OR_RESTORATION_UNRESOLVED")
	}
	if UnpairedExperimentBusy() {
		return fmt.Errorf("unpaired experiment owner active")
	}
	if ipadUpgradeReserved.Load() {
		return fmt.Errorf("signed maintenance upgrade reserved")
	}
	if IPadSoftwareReconnectAdmissionBusy() || !IPadSoftwareReconnectCanConnect() {
		return fmt.Errorf("software reconnect or its restoration unresolved")
	}
	if IPadCandidateBusy() || IPadCandidateSnapshot().Stage != 0 {
		return fmt.Errorf("restore candidate stage before AMDS diagnostics")
	}
	if NetworkOnlyAvailable() || NetworkOnlySnapshot().Busy {
		return fmt.Errorf("network-only policy owns AMDS; restore it before diagnostics")
	}
	if requested != "running" && requested != "stopped" {
		return fmt.Errorf("invalid AMDS mode diagnostic")
	}
	if s := connectionMonitor(); s != nil && s.snapshot().Status == "USB_RECOVERY_WAITING" {
		return fmt.Errorf("iPad cleanup unresolved")
	}
	ids, complete := idlePnPIDs(ctx)
	_, presence := idleUSBPresenceFromIDs(onlyIPadIDs(ids), complete)
	target := presence.identity
	if target == "" {
		target, _ = lastAttemptIdentity.Load().(string)
	}
	if target == "" || !strings.HasPrefix(strings.ToUpper(target), `USB\VID_05AC&PID_12AB\`) {
		return fmt.Errorf("current or previously authorized iPad required")
	}
	attemptBefore := currentSoftwareAttempt()
	amdsDiagnosticJob.Lock()
	if amdsDiagnosticJob.Running {
		amdsDiagnosticJob.Unlock()
		return fmt.Errorf("AMDS diagnostic already running")
	}
	// A successfully admitted first probe owns the ordinary connection path
	// until the entire two-state batch or verified recovery finishes.
	amdsDiagnosticBatch.hold()
	amdsDiagnosticJob.Running, amdsDiagnosticJob.Pending = true, true
	amdsDiagnosticJob.StartedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	amdsDiagnosticJob.Phase, amdsDiagnosticJob.Requested, amdsDiagnosticJob.TargetRoot = "awaiting_cleanup", requested, target
	amdsDiagnosticJob.Result = nil
	amdsDiagnosticJob.LocalTrustTrial = localTrial
	amdsDiagnosticJob.AttemptBefore, amdsDiagnosticJob.AttemptAfter = attemptBefore, 0
	amdsDiagnosticJob.TrialObservation = LocalTrustServiceTrial{}
	amdsDiagnosticJob.JobContext, amdsDiagnosticJob.JobCancel = context.WithCancel(ctx)
	stop := amdsDiagnosticJob.AttemptStop
	amdsDiagnosticJob.Unlock()
	time.AfterFunc(200*time.Millisecond, func() {
		if stop != nil {
			stop()
		}
		signalDiagnosticLoop()
	})
	return nil
}

func signalDiagnosticLoop() {
	select {
	case connectionChanged <- struct{}{}:
	default:
	}
}
func AMDSModeDiagnosticSnapshot() AMDSModeDiagnosticJob {
	amdsDiagnosticJob.Lock()
	defer amdsDiagnosticJob.Unlock()
	return AMDSModeDiagnosticJob{Running: amdsDiagnosticJob.Running, StartedUTC: amdsDiagnosticJob.StartedUTC, Phase: amdsDiagnosticJob.Phase, Result: amdsDiagnosticJob.Result, OrdinaryIPadConnectionHeld: IPadModeDiagnosticHeld()}
}
func AMDSModeDiagnosticActive() bool {
	amdsDiagnosticJob.Lock()
	defer amdsDiagnosticJob.Unlock()
	return amdsDiagnosticJob.Running
}
func AMDSModeDiagnosticPending() bool {
	amdsDiagnosticJob.Lock()
	defer amdsDiagnosticJob.Unlock()
	return amdsDiagnosticJob.Pending
}
func diagnosticPhase(phase string) {
	amdsDiagnosticJob.Lock()
	amdsDiagnosticJob.Phase = phase
	amdsDiagnosticJob.Unlock()
}

func RunPendingAMDSModeDiagnostic(ctx context.Context, version, dir string, cleanupSafe bool) bool {
	amdsDiagnosticJob.Lock()
	if !amdsDiagnosticJob.Pending {
		amdsDiagnosticJob.Unlock()
		return false
	}
	amdsDiagnosticJob.Pending = false
	requested, root := amdsDiagnosticJob.Requested, amdsDiagnosticJob.TargetRoot
	localTrial := amdsDiagnosticJob.LocalTrustTrial
	jobCtx, jobCancel := amdsDiagnosticJob.JobContext, amdsDiagnosticJob.JobCancel
	amdsDiagnosticJob.Unlock()
	defer jobCancel()
	var r AMDSModeDiagnostic
	if !cleanupSafe {
		r.Error = "PREVIOUS_IPAD_CLEANUP_UNCONFIRMED"
	} else {
		// The previous attempt has been cancelled and cleaned up. Mode control
		// must use this job's context, never that previous attempt's context.
		// Reserve ten seconds of the 120-second local trial budget for recovery.
		// A blocked Windows API is not evidence that restoration completed.
		budget := 120 * time.Second
		if localTrial {
			budget = 110 * time.Second
		}
		jobCtx, cancelTrial := context.WithTimeout(jobCtx, budget)
		defer cancelTrial()
		SetConnectionContext(jobCtx)
		defer SetConnectionContext(ctx)
		r = runAMDSModeDiagnostic(jobCtx, version, requested, dir, root)
	}
	afterAttempt := currentSoftwareAttempt()
	noChangeSafe := localTrustTrialSafeNoChange(cleanupSafe, r.Error, r.NoServiceChangeNoReceipt)
	amdsDiagnosticJob.Lock()
	amdsDiagnosticJob.Result, amdsDiagnosticJob.Running, amdsDiagnosticJob.Phase = &r, false, "complete"
	amdsDiagnosticJob.AttemptAfter = afterAttempt
	if localTrial {
		amdsDiagnosticJob.Phase = localTrustTrialCompletion(cleanupSafe, r.Restored, r.RestoreError)
		if noChangeSafe {
			amdsDiagnosticJob.Phase = "failed_before_service_change"
			if r.Error == "DIAGNOSTIC_CANCELLED_BEFORE_CHANGE" {
				amdsDiagnosticJob.Phase = "cancelled_before_service_change"
			}
		}
	}
	amdsDiagnosticJob.Unlock()
	if localTrial && (localTrustTrialCanResume(cleanupSafe, r.Restored, r.RestoreError) || noChangeSafe) {
		ReleaseIPadModeDiagnosticHoldAfterRecovery(true)
	}
	signalDiagnosticLoop()
	return true
}

// The caller must be the authenticated diagnostic endpoint. This test never
// changes startup type, pairs a device, or disables any portable-device node.
// Already-active NCM is reported as such; it cannot prove an actual mode switch.
func runAMDSModeDiagnostic(ctx context.Context, version, requested, dir, root string) (r AMDSModeDiagnostic) {
	amdsDiagnosticMu.Lock()
	defer amdsDiagnosticMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	started := time.Now()
	defer func() { r.ElapsedMS = time.Since(started).Milliseconds() }()
	r.RequestedState = requested
	journalAttempted := false
	defer func() {
		r.NoServiceChangeNoReceipt = localTrustTrialNoChangeProof(journalAttempted, r.Error, func() error {
			_, err := readAMDSDiagnosticReceipt(filepath.Join(dir, "amds-diagnostic.json"))
			return err
		})
		// Preserve the older cancellation field without calling other failures cancellation.
		r.CancelledBeforeChange = r.Error == "DIAGNOSTIC_CANCELLED_BEFORE_CHANGE" && r.NoServiceChangeNoReceipt
	}()
	if ctx.Err() != nil {
		r.Error = "DIAGNOSTIC_CANCELLED_BEFORE_CHANGE"
		return
	}
	if requested != "running" && requested != "stopped" {
		r.Error = "INVALID_DIAGNOSTIC_SERVICE_STATE"
		return
	}
	m, e := mgr.Connect()
	if e != nil {
		r.Error = "SERVICE_MANAGER_UNAVAILABLE"
		return
	}
	defer m.Disconnect()
	s, e := m.OpenService("Apple Mobile Device Service")
	if e != nil {
		r.Error = "OFFICIAL_APPLE_SERVICE_NOT_FOUND"
		return
	}
	defer s.Close()
	status, e := s.Query()
	config, ce := s.Config()
	if e != nil || ce != nil || (status.State != svc.Running && status.State != svc.Stopped) {
		r.Error = "INITIAL_SERVICE_STATE_NOT_STABLE"
		return
	}
	r.Before, r.OriginalStartType = uint32(status.State), config.StartType
	publishLocalTrustTrialObservation(r)
	journalAttempted = true
	if e := saveAMDSDiagnosticJournal(dir, r.Before, r.OriginalStartType); e != nil {
		r.Error = "SERVICE_RESTORE_JOURNAL_UNAVAILABLE"
		return
	}
	RecordTrustOperation(currentSoftwareAttempt(), "apple_service_lease_begin")
	defer func() { RecordTrustOperation(currentSoftwareAttempt(), "apple_service_lease_end") }()
	defer func() {
		diagnosticPhase("restoring_service")
		restoreCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e := diagnosticServiceState(restoreCtx, s, status.State); e != nil {
			r.RestoreError = "SERVICE_STATE_RESTORE_FAILED"
			return
		}
		after, e := s.Query()
		cfg, ce := s.Config()
		r.After = uint32(after.State)
		r.Restored = e == nil && ce == nil && after.State == status.State && cfg.StartType == config.StartType
		if !r.Restored {
			r.RestoreError = "SERVICE_STATE_OR_START_TYPE_RESTORE_UNCONFIRMED"
		} else if os.Remove(filepath.Join(dir, "amds-diagnostic.json")) != nil {
			r.RestoreError = "SERVICE_RESTORE_JOURNAL_REMOVE_FAILED"
		}
		publishLocalTrustTrialObservation(r)
	}()
	wanted := svc.Running
	if requested == "stopped" {
		wanted = svc.Stopped
	}
	if e := diagnosticServiceState(ctx, s, wanted); e != nil {
		r.Error = "SERVICE_TEST_STATE_UNAVAILABLE"
		return
	}
	r.During = uint32(wanted) // diagnosticServiceState returned only after readback.
	publishLocalTrustTrialObservation(r)
	if err := waitDiagnosticReplug(ctx, root); err != "" {
		r.Error = err
		return
	}
	diagnosticPhase("switching_mode")
	a := &ConnectionAuthorization{}
	a.BeginSecurityAttempt(ctx, cancel)
	defer a.FinishSecurityAttempt()
	if !a.Allow() {
		r.Error = "USB_AUTHORIZATION_REQUIRED"
		return
	}
	// Physical reattachment and authorization may take a long time. Record an
	// observed state immediately before the mode request, never its target.
	during, e := s.Query()
	if e == nil {
		r.During = uint32(during.State)
	}
	if e != nil || during.State != wanted {
		r.Error = "SERVICE_STATE_CHANGED_DURING_TEST"
		return
	}
	stateChanged := false
	// The mode implementation invokes consent immediately before 0x52. Repeat
	// the observation there too, after device opening and GET_MODE complete.
	modeConsent := func() bool {
		if !a.Allow() {
			return false
		}
		observed, qe := s.Query()
		if qe == nil {
			r.During = uint32(observed.State)
		}
		stateChanged = qe != nil || observed.State != wanted
		return !stateChanged
	}
	probe := RunNetworkOnlyAppleControl(version, modeConsent, nil, nil)
	r.Mode = &probe
	afterMode, e := s.Query()
	if stateChanged || e != nil || afterMode.State != wanted {
		r.Error = "SERVICE_STATE_CHANGED_DURING_TEST"
		return
	}
	if probe.Status != "NCM_DESCRIPTORS_PRESENT" && probe.Status != "NCM_DESCRIPTORS_AFTER_REQUEST" {
		r.Error = probe.Status
	}
	return
}

func diagnosticServiceState(ctx context.Context, s *mgr.Service, wanted svc.State) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	status, e := s.Query()
	if e != nil {
		return e
	}
	if status.State == wanted {
		return nil
	}
	if wanted == svc.Running {
		e = s.Start()
	} else {
		_, e = s.Control(svc.Stop)
	}
	if e != nil {
		return e
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, e = s.Query()
		if e != nil {
			return e
		}
		if status.State == wanted {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("service wait: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

type amdsDiagnosticJournal struct {
	Version   int    `json:"version"`
	State     uint32 `json:"original_state"`
	StartType uint32 `json:"original_start_type"`
}

func saveAMDSDiagnosticJournal(dir string, state, startType uint32) error {
	b, e := json.Marshal(amdsDiagnosticJournal{1, state, startType})
	if e != nil {
		return e
	}
	f, e := os.OpenFile(filepath.Join(dir, "amds-diagnostic.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}

// The protected receipt is also replayed at the next launch after a crash.
// Startup type is read back, never overwritten by this diagnostic.
func RecoverAMDSModeDiagnostic(dir string) error {
	path := filepath.Join(dir, "amds-diagnostic.json")
	p, e := readAMDSDiagnosticReceipt(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil || len(p) > 1024 {
		return fmt.Errorf("AMDS receipt unavailable")
	}
	var j amdsDiagnosticJournal
	dec := json.NewDecoder(strings.NewReader(string(p)))
	dec.DisallowUnknownFields()
	if dec.Decode(&j) != nil || j.Version != 1 || (j.State != uint32(svc.Running) && j.State != uint32(svc.Stopped)) || j.StartType > 4 {
		return fmt.Errorf("AMDS receipt invalid")
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return fmt.Errorf("AMDS receipt trailing data")
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService("Apple Mobile Device Service")
	if e != nil {
		return e
	}
	defer s.Close()
	cfg, e := s.Config()
	if e != nil || cfg.StartType != j.StartType {
		return fmt.Errorf("AMDS startup configuration changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e := diagnosticServiceState(ctx, s, svc.State(j.State)); e != nil {
		return e
	}
	status, e := s.Query()
	if e != nil || uint32(status.State) != j.State {
		return fmt.Errorf("AMDS restoration not verified")
	}
	return os.Remove(path)
}

func waitDiagnosticReplug(ctx context.Context, root string) string {
	diagnosticPhase("awaiting_detach")
	var gate amdsReplugGate
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		ids, complete := idlePnPIDs(ctx)
		_, p := idleUSBPresenceFromIDs(onlyIPadIDs(ids), complete)
		ready, changed := gate.observe(time.Now(), p, root)
		if changed {
			return "DIAGNOSTIC_USB_TARGET_CHANGED"
		}
		if gate.detached {
			diagnosticPhase("awaiting_attach")
		}
		if ready {
			snapshot := Inspect()
			if networkOnlyUSBEligible(snapshot) && strings.EqualFold(exactIPadRoot(snapshot), root) {
				return ""
			}
		}

		select {
		case <-ctx.Done():
			return "DIAGNOSTIC_REPLUG_TIMED_OUT_OR_CANCELLED"
		case <-connectionChanged:
		case <-ticker.C:
		}
	}
}

func CancelAMDSModeDiagnostic() {
	amdsDiagnosticJob.Lock()
	defer amdsDiagnosticJob.Unlock()
	if amdsDiagnosticJob.Running && amdsDiagnosticJob.JobCancel != nil {
		amdsDiagnosticJob.Phase = "cancelling_and_restoring"
		amdsDiagnosticJob.JobCancel()
		signalDiagnosticLoop()
	}
}

func readAMDSDiagnosticReceipt(path string) ([]byte, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	var info windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(h, &info); e != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("unsafe AMDS receipt")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("AMDS receipt handle unavailable")
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1025))
}
