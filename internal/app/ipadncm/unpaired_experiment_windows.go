//go:build windows && amd64

package ipadncm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// A fixed owner request, not persistent policy. The callback is compiled into
// the publisher's fixed RPC handler; remote clients cannot select its path or
// provide a filename, native root, pairing identity or claimed absence.
var unpairedExperiment struct {
	sync.Mutex
	model                                   unpairedExperimentModel
	inspectMetadata                         func(Snapshot) (UnpairedPairMetadata, error)
	command                                 string
	timer                                   *time.Timer
	stop                                    context.CancelFunc
	generation                              uint64
	dir, system                             string
	borrowed                                bool
	originalAvailable, originalEnabled      bool
	originalStatus, originalNotice          string
	originalServiceState, originalStartType uint32
	attachment                              usbDescriptorAttachment
	attemptContext                          context.Context
}

func UnpairedExperimentSnapshot() UnpairedExperimentStatus {
	unpairedExperiment.Lock()
	defer unpairedExperiment.Unlock()
	r := unpairedExperiment.model.status
	r.DiagnosticStartupHeld = unpairedDiagnosticShouldHold(unpairedDiagnosticStartupHoldState.Load(), unpairedExperiment.model, time.Now())
	if r.LastAttempt != nil {
		copy := *r.LastAttempt
		if copy.InitialDescriptor != nil {
			d := *copy.InitialDescriptor
			d.Errors = append([]string(nil), d.Errors...)
			if d.SerialFailureShape != nil {
				shape := *d.SerialFailureShape
				d.SerialFailureShape = &shape
			}
			copy.InitialDescriptor = &d
		}
		r.LastAttempt = &copy
	}
	if r.State == "" {
		r.State = "OFF"
	}
	r.Metadata = append([]UnpairedMetadataObservation(nil), r.Metadata...)
	r.Events = append([]UnpairedExperimentEvent(nil), r.Events...)
	return r
}
func UnpairedExperimentBusy() bool {
	s := UnpairedExperimentSnapshot()
	return s.Pending || s.Busy || s.Blocked || s.State == "PREPARED" || s.State == "BOUND" || s.State == "FINISH_PENDING" || s.State == "RESTORE_PENDING"
}
func UnpairedExperimentPending() bool { return UnpairedExperimentSnapshot().Pending }
func UnpairedExperimentCanConnect() bool {
	unpairedExperiment.Lock()
	defer unpairedExperiment.Unlock()
	s := unpairedExperiment.model.status
	if s.State == "" {
		return true
	}
	return unpairedExperiment.model.live(time.Now()) && s.State == "PREPARED"
}
func RequestUnpairedExperimentPreparation(inspect func(Snapshot) (UnpairedPairMetadata, error)) error {
	return fmt.Errorf("LEGACY_UNPAIRED_EXPERIMENT_RETIRED")
}

func RequestUnpairedExperimentFinish() error {
	ipadActionAdmission.Lock()
	defer ipadActionAdmission.Unlock()
	unpairedExperiment.Lock()
	if unpairedExperiment.model.status.State == "" || unpairedExperiment.model.status.State == "FINISHED" {
		unpairedExperiment.Unlock()
		return fmt.Errorf("no unpaired experiment owner")
	}
	unpairedExperiment.model.stop("")
	unpairedExperiment.command = "finish"
	stop := unpairedExperiment.stop
	unpairedExperiment.Unlock()
	if stop != nil {
		stop()
	}
	signalDiagnosticLoop()
	return nil
}
func RecordUnpairedExperimentReplied() error {
	unpairedExperiment.Lock()
	defer unpairedExperiment.Unlock()
	m := &unpairedExperiment.model
	if !m.live(time.Now()) || m.status.State != "BOUND" || m.status.RepliedUTC != "" {
		return fmt.Errorf("unpaired experiment not bound or already replied")
	}
	m.status.RepliedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	return nil
}
func AttachUnpairedExperimentAttempt(stop context.CancelFunc) func() {
	unpairedExperiment.Lock()
	unpairedExperiment.stop = stop
	generation := unpairedExperiment.generation
	pending := unpairedExperiment.model.status.Pending
	unpairedExperiment.Unlock()
	if pending && stop != nil {
		stop()
	}
	return func() {
		unpairedExperiment.Lock()
		if unpairedExperiment.generation == generation {
			unpairedExperiment.stop = nil
			unpairedExperiment.attemptContext = nil
		}
		unpairedExperiment.Unlock()
	}
}
func stopUnpairedExperiment(reason string) {
	unpairedFeatureLease.Store(false)
	unpairedExperiment.Lock()
	unpairedExperiment.model.stop(reason)
	unpairedExperiment.command = "finish"
	stop := unpairedExperiment.stop
	unpairedExperiment.Unlock()
	if stop != nil {
		stop()
	}
	signalDiagnosticLoop()
}

// PREP must not adopt another connection's journal or owned originals. The
// existing fixed recovery store has already been locked by the main owner.
func unpairedPreparationNative(ctx context.Context, dir string) error {
	if ctx.Err() != nil || !networkOnlyDriverStoreProtected(dir) {
		return fmt.Errorf("unpaired protected owner unavailable")
	}
	for _, name := range []string{"network-only-receipt.json", "pending.json", "application-session.json"} {
		_, e := readProtectedNetworkOnlyFile(filepath.Join(dir, name), 65536)
		if !os.IsNotExist(e) {
			return fmt.Errorf("unpaired preexisting recovery obligation or unreadable file")
		}
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) > 4096 {
		return fmt.Errorf("unpaired recovery inventory unavailable")
	}
	for _, n := range entries {
		if strings.HasPrefix(n.Name(), "network-grouping-") && strings.HasSuffix(n.Name(), ".json") {
			return fmt.Errorf("unpaired preexisting configured grouping")
		}
	}
	ids, ok := idlePnPIDs(ctx)
	if !ok {
		return fmt.Errorf("unpaired native absence unreadable")
	}
	for _, id := range ids {
		if strings.HasPrefix(strings.ToUpper(id), `USB\VID_05AC&PID_12AB`) {
			return fmt.Errorf("prepare requires iPad absent; no device permission granted")
		}
	}
	if e := verifyInstalledAppleControlDriver(); e != nil {
		return fmt.Errorf("unpaired official driver hash unproven")
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	service, e := m.OpenService("Apple Mobile Device Service")
	if e != nil {
		return e
	}
	defer service.Close()
	state, e := service.Query()
	if e != nil || state.State != svc.Running && state.State != svc.Stopped {
		return fmt.Errorf("unpaired service state unstable")
	}
	cfg, e := service.Config()
	if e != nil || cfg.StartType != 2 && cfg.StartType != 3 {
		return fmt.Errorf("unpaired service policy unsupported")
	}
	unpairedExperiment.Lock()
	unpairedExperiment.originalServiceState = uint32(state.State)
	unpairedExperiment.originalStartType = cfg.StartType
	unpairedExperiment.Unlock()
	return nil
}
func RunPendingUnpairedExperiment(ctx context.Context, dir, system string, cleanupSafe bool) bool {
	unpairedExperiment.Lock()
	if !unpairedExperiment.model.status.Pending || ipadUpgradeReserved.Load() {
		unpairedExperiment.Unlock()
		return false
	}
	command := unpairedExperiment.command
	unpairedExperiment.model.status.Pending = false
	unpairedExperiment.model.status.Busy = true
	unpairedExperiment.Unlock()
	if command == "finish" {
		_ = FinishUnpairedExperimentOwner(ctx, dir, system, cleanupSafe)
		return true
	}
	e := fmt.Errorf("unpaired prior session cleanup unresolved")
	if cleanupSafe && ctx.Err() == nil {
		e = unpairedPreparationNative(ctx, dir)
	}
	if e == nil {
		networkOnly.Lock()
		if networkOnly.dir != dir || networkOnly.system != system || networkOnly.busy || networkOnly.pending || networkOnly.blocked || networkOnly.available {
			networkOnly.Unlock()
			unpairedExperiment.Lock()
			unpairedExperiment.model.reject(fmt.Errorf("unpaired original owner state changed"))
			unpairedExperiment.Unlock()
			return true
		}
		unpairedExperiment.Lock()
		unpairedExperiment.dir, unpairedExperiment.system = dir, system
		unpairedExperiment.borrowed = true
		unpairedExperiment.originalAvailable, unpairedExperiment.originalEnabled = networkOnly.available, networkOnly.enabled
		unpairedExperiment.originalStatus, unpairedExperiment.originalNotice = networkOnly.status, networkOnly.notice
		unpairedExperiment.Unlock()
		// Temporary experiment permission; the saved choice is neither rewritten
		// nor interpreted as permanent ON, and no dual-mode evidence is fabricated.
		networkOnly.available, networkOnly.enabled = true, true
		networkOnly.status = "UNPAIRED_EXPERIMENT_PREPARING"
		networkOnly.notice = ""
		networkOnly.Unlock()
		e = applyNetworkOnlyService(ctx, dir)
		if e == nil {
			r, re := readNetworkOnlyReceipt(dir)
			unpairedExperiment.Lock()
			matched := re == nil && r.ServiceState == unpairedExperiment.originalServiceState && r.StartType == unpairedExperiment.originalStartType && len(r.Nodes) == 0
			unpairedExperiment.Unlock()
			if !matched {
				e = fmt.Errorf("unpaired service original receipt mismatch")
			}
		}
	}
	if e != nil {
		unpairedExperiment.Lock()
		borrowed := unpairedExperiment.borrowed
		unpairedExperiment.Unlock()
		if borrowed {
			stopUnpairedExperiment("PREPARE_FAILED")
			_ = FinishUnpairedExperimentOwner(ctx, dir, system, cleanupSafe)
		} else {
			unpairedExperiment.Lock()
			unpairedExperiment.model.reject(e)
			unpairedExperiment.Unlock()
		}
		return true
	}
	unpairedExperiment.Lock()
	if unpairedExperiment.command != "prepare" || unpairedExperiment.model.status.Pending {
		unpairedExperiment.Unlock()
		_ = FinishUnpairedExperimentOwner(ctx, dir, system, cleanupSafe)
		return true
	}
	now := time.Now()
	unpairedExperiment.model.expires = now.Add(10 * time.Minute)
	unpairedExperiment.model.status.State = "PREPARED"
	unpairedExperiment.model.status.Busy = false
	unpairedExperiment.model.status.PreparedUTC = now.UTC().Format(time.RFC3339Nano)
	unpairedExperiment.model.status.ExpiresUTC = unpairedExperiment.model.expires.UTC().Format(time.RFC3339Nano)
	generation := unpairedExperiment.generation
	unpairedExperiment.timer = time.AfterFunc(10*time.Minute, func() {
		unpairedExperiment.Lock()
		current := unpairedExperiment.generation == generation && unpairedExperiment.model.status.State != "FINISHED"
		unpairedExperiment.Unlock()
		if current {
			stopUnpairedExperiment("LEASE_EXPIRED")
		}
	})
	unpairedExperiment.Unlock()
	signalDiagnosticLoop()
	return true
}

// Called once and only AFTER the ordinary consent path returns true. The
// fresh physical attachment is the permission scope; a hash is not permission.
func BindUnpairedExperimentAfterConsent() error {
	unpairedExperiment.Lock()
	if unpairedExperiment.model.status.State == "" || unpairedExperiment.model.status.State == "FINISHED" && !unpairedExperiment.borrowed {
		unpairedExperiment.Unlock()
		return nil
	}
	prepared := unpairedExperiment.model.live(time.Now()) && unpairedExperiment.model.status.State == "PREPARED"
	inspect := unpairedExperiment.inspectMetadata
	unpairedExperiment.Unlock()
	if !prepared || inspect == nil {
		return fmt.Errorf("unpaired experiment is not prepared for one attempt")
	}
	before := Inspect()
	if !networkOnlyUSBEligible(before) {
		stopUnpairedExperiment("FRESH_DEVICE_UNPROVEN")
		return fmt.Errorf("unpaired fresh device unproven")
	}
	root := exactIPadRoot(before)
	official, native := networkOnlyDriverRootHealthy(before, root)
	metadata, e := inspect(before)
	after := Inspect()
	if e != nil {
		stopUnpairedExperiment("PAIR_METADATA_CHECK: " + unpairedPublicProblem(e))
		return fmt.Errorf("unpaired metadata: %s", unpairedPublicProblem(e))
	}
	if !official || !native || !descriptorAttachment(before).same(descriptorAttachment(after)) || verifyInstalledAppleControlDriver() != nil || !validUnpairedMetadata(metadata, before.Devices[0].USBSerialSHA256) {
		stopUnpairedExperiment("FRESH_ADMISSION_OR_METADATA_UNPROVEN")
		return fmt.Errorf("unpaired fresh admission or metadata unproven")
	}
	unpairedExperiment.Lock()
	e = unpairedExperiment.model.bind(time.Now(), root, before.Devices[0].USBSerialSHA256, metadata)
	if e == nil {
		unpairedExperiment.attachment = descriptorAttachment(after)
		unpairedExperiment.attemptContext = connectionContext()
	}
	unpairedExperiment.Unlock()
	if e != nil {
		stopUnpairedExperiment("ONE_ATTEMPT_SCOPE_UNPROVEN")
		return e
	}
	if _, problem := unpairedExperimentDriverAdmission(after); problem != "" {
		stopUnpairedExperiment(problem)
		return fmt.Errorf("%s", problem)
	}
	unpairedFeatureLease.Store(true)
	return nil
}

// This separate, explicit experiment authorization replaces no normal I7
// stage/dual-mode proof. It never grants the ordinary owner's initial-apply
// permission or accepts a service-only receipt as that owner's root receipt.
func unpairedExperimentDriverAdmission(before Snapshot) (bool, string) {
	unpairedExperiment.Lock()
	m := unpairedExperiment.model
	dir := unpairedExperiment.dir
	originalState, originalStart := unpairedExperiment.originalServiceState, unpairedExperiment.originalStartType
	binding := unpairedExperiment.attachment
	ctx := unpairedExperiment.attemptContext
	unpairedExperiment.Unlock()
	if !NetworkOnlyEnabled() || !NetworkOnlyCanConnect() || !m.live(time.Now()) || m.status.State != "BOUND" || ctx == nil || ctx.Err() != nil || !networkOnlyUSBEligible(before) || !binding.same(descriptorAttachment(before)) || !strings.EqualFold(m.root, exactIPadRoot(before)) || !networkOnlyDriverStoreProtected(dir) {
		return false, "UNPAIRED_EXPERIMENT_NATIVE_SCOPE_UNPROVEN"
	}
	fresh := Inspect()
	official, native := networkOnlyDriverRootHealthy(fresh, m.root)
	if !official || !native || !binding.same(descriptorAttachment(fresh)) || verifyInstalledAppleControlDriver() != nil {
		return false, "UNPAIRED_EXPERIMENT_OFFICIAL_ROOT_UNPROVEN"
	}
	r, e := readNetworkOnlyReceipt(dir)
	if e != nil || r.ServiceState != originalState || r.StartType != originalStart {
		return false, "UNPAIRED_EXPERIMENT_RECEIPT_UNPROVEN"
	}
	for _, n := range r.Nodes {
		if !strings.EqualFold(n.Root, m.root) {
			return false, "UNPAIRED_EXPERIMENT_RECEIPT_WRONG_ROOT"
		}
	}
	manager, e := mgr.Connect()
	if e != nil {
		return false, "UNPAIRED_EXPERIMENT_SERVICE_UNREADABLE"
	}
	defer manager.Disconnect()
	service, e := manager.OpenService("Apple Mobile Device Service")
	if e != nil {
		return false, "UNPAIRED_EXPERIMENT_SERVICE_MISSING"
	}
	defer service.Close()
	state, se := service.Query()
	cfg, ce := service.Config()
	if !unpairedExpectedServicePolicy(se == nil && ce == nil, originalState, originalStart, r.ServiceState, r.StartType, uint32(state.State), cfg.StartType) || ctx.Err() != nil {
		return false, "UNPAIRED_EXPERIMENT_STOPPED_POLICY_UNPROVEN"
	}
	unpairedExperiment.Lock()
	same := unpairedExperiment.model.live(time.Now()) && unpairedExperiment.model.root == m.root && unpairedExperiment.model.status.Attempts == 1
	unpairedExperiment.Unlock()
	if !same {
		return false, "UNPAIRED_EXPERIMENT_LEASE_CHANGED"
	}
	return true, ""
}
func UnpairedExperimentModeAllowedForCurrentDevice() (bool, string) {
	unpairedExperiment.Lock()
	active := unpairedExperiment.model.status.State != "" && unpairedExperiment.model.status.State != "FINISHED"
	unpairedExperiment.Unlock()
	if !active {
		return false, ""
	}
	if _, e := observeUnpairedMetadata("before_mode"); e != nil {
		return false, "UNPAIRED_EXPERIMENT_METADATA_UNPROVEN"
	}
	return unpairedExperimentDriverAdmission(Inspect())
}
func ObserveUnpairedExperimentMetadata() (UnpairedExperimentStatus, error) {
	return observeUnpairedMetadata("explicit_result")
}
func observeUnpairedMetadata(phase string) (UnpairedExperimentStatus, error) {
	unpairedExperiment.Lock()
	inspect := unpairedExperiment.inspectMetadata
	binding := unpairedExperiment.attachment
	digest := unpairedExperiment.model.status.SerialSHA256
	bound := unpairedExperiment.model.status.State == "BOUND"
	unpairedExperiment.Unlock()
	if !bound || inspect == nil {
		return UnpairedExperimentSnapshot(), nil // PREP grants no device scope or metadata result.
	}
	before := Inspect()
	v, e := inspect(before)
	after := Inspect()
	if e != nil {
		stopUnpairedExperiment("PAIR_METADATA_CHECK: " + unpairedPublicProblem(e))
		return UnpairedExperimentSnapshot(), fmt.Errorf("unpaired metadata: %s", unpairedPublicProblem(e))
	}
	if !binding.same(descriptorAttachment(before)) || !binding.same(descriptorAttachment(after)) || !validUnpairedMetadata(v, digest) {
		stopUnpairedExperiment("PAIR_METADATA_REAPPEARED_OR_UNPROVEN")
		return UnpairedExperimentSnapshot(), fmt.Errorf("unpaired result metadata scope absent or unproven")
	}
	unpairedExperiment.Lock()
	if !unpairedExperiment.model.live(time.Now()) || unpairedExperiment.model.status.State != "BOUND" || unpairedExperiment.model.status.SerialSHA256 != digest {
		unpairedExperiment.Unlock()
		return UnpairedExperimentSnapshot(), fmt.Errorf("unpaired metadata sample lease changed")
	}
	unpairedExperiment.model.metadata(time.Now(), phase, v)
	unpairedExperiment.Unlock()
	return UnpairedExperimentSnapshot(), nil
}
func FinishUnpairedExperimentOwner(_ context.Context, dir, system string, cleanupSafe bool) error {
	unpairedFeatureLease.Store(false)
	unpairedExperiment.Lock()
	if unpairedExperiment.model.status.State == "" || unpairedExperiment.model.status.State == "FINISHED" && !unpairedExperiment.borrowed {
		unpairedExperiment.Unlock()
		return nil
	}
	if unpairedExperiment.timer != nil {
		unpairedExperiment.timer.Stop()
		unpairedExperiment.timer = nil
	}
	borrowed := unpairedExperiment.borrowed
	originalAvailable, originalEnabled := unpairedExperiment.originalAvailable, unpairedExperiment.originalEnabled
	originalStatus, originalNotice := unpairedExperiment.originalStatus, unpairedExperiment.originalNotice
	unpairedExperiment.Unlock()
	e := unpairedRestoreOwned(cleanupSafe, borrowed, func() error {
		if err := RestoreNetworkOnly(dir, system); err != nil {
			return err
		}
		_, re := readNetworkOnlyReceipt(dir)
		if !os.IsNotExist(re) {
			return fmt.Errorf("unpaired restore receipt absence unproven")
		}
		return nil
	})
	if e == nil && borrowed {
		networkOnly.Lock()
		networkOnly.available, networkOnly.enabled = originalAvailable, originalEnabled
		networkOnly.status, networkOnly.notice = originalStatus, originalNotice
		networkOnly.blocked = false
		networkOnly.Unlock()
	}
	unpairedExperiment.Lock()
	unpairedExperiment.model.restored(e)
	if e == nil {
		unpairedExperiment.borrowed = false
	}
	unpairedExperiment.Unlock()
	signalDiagnosticLoop()
	return e
}
func recordUnpairedExperimentEvent(kind string) {
	unpairedExperiment.Lock()
	unpairedExperiment.model.event(time.Now(), kind)
	unpairedExperiment.Unlock()
}

func unpairedExperimentOwnsNetworkOnly() bool {
	unpairedExperiment.Lock()
	defer unpairedExperiment.Unlock()
	return unpairedExperiment.borrowed
}
func ValidateUnpairedExperimentAfterMode() error {
	if !unpairedExperimentOwnsNetworkOnly() {
		return nil
	}
	_, e := observeUnpairedMetadata("after_mode")
	return e
}

// Call only after FinishSecurityAttempt joined the authorization watcher, so
// these scalar observations cannot race with its consent/security updates.
func CompleteUnpairedExperimentAttempt(stage, problem string, a *ConnectionAuthorization) {
	if !unpairedExperimentOwnsNetworkOnly() {
		return
	}
	outcome := UnpairedAttemptDiagnostic{Stage: diagnosticCode(stage), Error: diagnosticCode(problem)}
	if a != nil {
		outcome.ConsentStatus = diagnosticCode(a.ConsentStatus)
		outcome.SecurityFailure = diagnosticCode(a.SecurityFailure())
		outcome.AllowedThisConnection = a.Once
		outcome.USBInfoMatched = a.USBInfoMatched
		if a.InitialUSB != nil {
			d := unpairedDescriptorDiagnostic(*a.InitialUSB)
			outcome.InitialDescriptor = &d
		}
	}
	unpairedExperiment.Lock()
	m := &unpairedExperiment.model
	outcome.MetadataError = unpairedMetadataFailureCode(m.status.FirstFailure)
	m.status.LastAttempt = &outcome
	if m.status.FirstFailure == "" && problem != "" {
		reason := outcome.Error
		if outcome.ConsentStatus != "" && outcome.ConsentStatus != "USB_ALLOWED" {
			reason = outcome.ConsentStatus
		}
		m.status.FirstFailure = reason
		m.status.Problem = reason
	}
	unpairedExperiment.Unlock()
	stopUnpairedExperiment("ONE_ATTEMPT_COMPLETE")
}
func UnpairedDiagnosticStartupHeld() bool {
	unpairedExperiment.Lock()
	defer unpairedExperiment.Unlock()
	return unpairedDiagnosticShouldHold(unpairedDiagnosticStartupHoldState.Load(), unpairedExperiment.model, time.Now())
}
func unpairedDescriptorDiagnostic(s Snapshot) UnpairedDescriptorDiagnostic {
	d := UnpairedDescriptorDiagnostic{DeviceCount: min(len(s.Devices), 64), Error: diagnosticCode(s.Error), Eligible: networkOnlyUSBEligible(s)}
	if len(s.Devices) != 1 {
		return d
	}
	v := s.Devices[0]
	d.Verified = v.USBDescriptorIdentityVerified
	d.CurrentConfiguration = v.CurrentConfiguration
	d.SerialSHA256 = diagnosticDigest(v.USBSerialSHA256)
	d.SerialStatus = diagnosticCode(v.USBSerialReadStatus)
	d.ProductStatus = diagnosticCode(v.USBProductReadStatus)
	if v.USBSerialFailureShape != nil {
		shape := *v.USBSerialFailureShape
		d.SerialFailureShape = &shape
	}
	for _, e := range v.Errors {
		if len(d.Errors) >= 16 {
			break
		}
		d.Errors = append(d.Errors, diagnosticCode(e))
	}
	return d
}

// Explicit current readback is available after FINISHED/REJECTED too. It grants
// no consent and neither arms an experiment nor changes its lease/owner state.
// The publisher supplies the fixed metadata reader, never remote input paths.
func InspectUnpairedExperimentPreflight(inspect func(Snapshot) (UnpairedPairMetadata, error)) UnpairedExperimentPreflight {
	out := UnpairedExperimentPreflight{ObservedUTC: time.Now().UTC().Format(time.RFC3339Nano), DiagnosticStartupHeld: UnpairedDiagnosticStartupHeld()}
	before := Inspect()
	out.Before = unpairedDescriptorDiagnostic(before)
	if !out.Before.Eligible {
		out.Error = "UNPAIRED_FRESH_DESCRIPTOR_UNPROVEN"
		return out
	}
	root := exactIPadRoot(before)
	out.OfficialRootHealthy, out.NativeRootHealthy = networkOnlyDriverRootHealthy(before, root)
	out.DriverHashVerified = verifyInstalledAppleControlDriver() == nil
	if !out.OfficialRootHealthy || !out.NativeRootHealthy {
		out.Error = "UNPAIRED_FRESH_ROOT_UNPROVEN"
	}
	if !out.DriverHashVerified && out.Error == "" {
		out.Error = "UNPAIRED_PINNED_DRIVER_HASH_UNPROVEN"
	}
	if inspect == nil {
		out.MetadataError = "UNPAIRED_METADATA_READER_UNAVAILABLE"
	} else {
		metadata, e := inspect(before)
		if e != nil {
			out.MetadataError = diagnosticCode(e.Error())
		} else if !validUnpairedMetadata(metadata, before.Devices[0].USBSerialSHA256) {
			out.MetadataError = "UNPAIRED_METADATA_SCOPE_UNPROVEN"
		} else {
			out.Metadata = &metadata
		}
	}
	after := Inspect()
	d := unpairedDescriptorDiagnostic(after)
	out.After = &d
	out.AttachmentStable = descriptorAttachment(before).same(descriptorAttachment(after))
	if !out.AttachmentStable {
		out.Metadata = nil
		out.Error = "UNPAIRED_FRESH_ATTACHMENT_CHANGED"
	}
	return out
}
