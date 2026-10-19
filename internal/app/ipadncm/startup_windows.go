//go:build windows && amd64

package ipadncm

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/diagnostics/grouptrial"
	"suhang/usbnet/internal/security/deviceguard"
)

func problemStatus(set windows.DevInfo, info *windows.DevInfoData) (string, string) {
	g, _ := windows.GUIDFromString("{4340a6c5-93fa-4706-972c-7b648008a5a7}")
	key := windows.DEVPROPKEY{FmtID: windows.DEVPROPGUID(g), PID: 12}
	var status, size uint32
	var typ windows.DEVPROPTYPE
	v, _, e := windows.NewLazySystemDLL("setupapi.dll").NewProc("SetupDiGetDevicePropertyW").Call(uintptr(set), uintptr(unsafe.Pointer(info)), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&status)), 4, uintptr(unsafe.Pointer(&size)), 0)
	if v == 0 {
		return "", eno(e)
	}
	if typ != windows.DEVPROP_TYPE_NTSTATUS || size != 4 {
		return "", "INVALID_PROPERTY_TYPE_OR_LENGTH"
	}
	return fmt.Sprintf("0x%08x", status), ""
}

type StartupSample struct {
	ElapsedMS int64    `json:"elapsed_ms"`
	Snapshot  Snapshot `json:"usb"`
}
type StartupResult struct {
	Protocol          string          `json:"protocol"`
	Version           string          `json:"version"`
	Started           string          `json:"started_utc"`
	Status            string          `json:"status"`
	ProductType       string          `json:"product_type,omitempty"`
	ProductVersion    string          `json:"product_version,omitempty"`
	MetadataError     string          `json:"metadata_error,omitempty"`
	IdentitySource    string          `json:"identity_source,omitempty"`
	Mux               MuxDiagnostic   `json:"apple_usb_query"`
	Before            Snapshot        `json:"before"`
	Samples           []StartupSample `json:"samples,omitempty"`
	DriverChanged     bool            `json:"driver_changed"`
	ModeRequestSent   bool            `json:"mode_request_sent"`
	ServicePaused     bool            `json:"service_paused"`
	NetworkVerified   bool            `json:"network_verified"`
	MoonlightVerified bool            `json:"moonlight_verified"`
}

// Read-only start diagnostics. Does not restart a devnode, touch driver/registry
// configuration, send mode or NCM class requests, or configure networking.
func RunStartupCheck(version string) StartupResult {
	return runStartupCheck(version, nil, nil, false, "", "standalone")
}

// Bind the follow-up check to the physical target used by this same launcher.
func RunStartupCheckFor(version string, target Snapshot) StartupResult {
	return runStartupCheck(version, &target, nil, false, "", "initial_after_mode")
}

// No saved log or previous launch is accepted as identity evidence. The caller
// supplies its in-memory mode result; sampling still checks hub/port/PID each time.
func RunStartupCheckAfterMode(version string, mode Result) StartupResult {
	return runStartupCheck(version, &mode.Before, &mode, false, "", "initial_after_mode")
}

func RunStartupCheckAfterModeEvents(version string, mode Result) StartupResult {
	return runStartupCheck(version, &mode.Before, &mode, true, "", "initial_after_mode")
}

// The recovery directory enables an owned-layout proof. An explicit current
// consent callback also enables strictly proven existing-layout wait completion.
// Neither path changes generic readiness or grants network access.
func RunStartupCheckAfterModeEventsForConfigured(version string, mode Result, recoveryDir string, consent ...func() bool) StartupResult {
	return runStartupCheck(version, &mode.Before, &mode, true, recoveryDir, "initial_after_mode", consent...)
}

func runStartupCheck(version string, expected *Snapshot, mode *Result, eventMode bool, configuredDir, checkKind string, consent ...func() bool) StartupResult {
	done := RecordConnectionOperation("native_start_check")
	defer done()
	ctx, cancel := context.WithTimeout(connectionContext(), 35*time.Second)
	defer cancel()
	r := StartupResult{Protocol: "SUHANG-IPAD-NCM-START-CHECK/1", Version: version, Started: time.Now().UTC().Format(time.RFC3339), Status: "INCOMPLETE"}
	checkStarted := time.Now()
	diagnostic := StartupReadinessDiagnostic{Attempt: currentSoftwareAttempt(), StartedUTC: r.Started, CheckKind: checkKind, EventMode: eventMode}
	defer func() {
		diagnostic.Status, diagnostic.ElapsedMS = r.Status, time.Since(checkStarted).Milliseconds()
		if diagnostic.ExitReason == "" {
			diagnostic.ExitReason = r.Status
		}
		startupReadinessHistory.record(diagnostic)
	}()
	r.Before = inventory(ctx)
	if r.Before.Error != "" || len(r.Before.Devices) != 1 {
		r.Status = "NEED_ONE_READABLE_APPLE_USB_DEVICE"
		return r
	}
	if expected != nil && !sameUSBTarget(*expected, r.Before) {
		r.Status = "USB_TARGET_CHANGED_BEFORE_START_CHECK"
		return r
	}
	recordConnectionStage("usb_enumerated", "one_readable_same_target_usb_device")
	target := r.Before.Devices[0]
	if mode != nil {
		if !modeResultIdentity(*mode, activeNCM(target.Configurations, target.CurrentConfiguration)) {
			r.Status = "CURRENT_MODE_IDENTITY_OR_ACTIVE_NCM_UNCONFIRMED"
			return r
		}
		r.ProductType, r.ProductVersion = mode.ProductType, mode.ProductVersion
		r.IdentitySource = "CURRENT_LAUNCHER_MODE_CHECK_SAME_USB_TARGET"
	} else {
		r.IdentitySource = "USB_PRODUCT_DESCRIPTOR_AND_QUALIFIED_LAYOUT"
		r.ProductType = usbIPadModel(target.USBProduct)
	}
	if !networkOnlyUSBEligible(r.Before) {
		r.Status = "IPAD_IDENTITY_UNCONFIRMED"
		return r
	}
	if !activeNCM(target.Configurations, target.CurrentConfiguration) {
		r.Status = "NCM_NOT_ACTIVE_NO_CHANGE"
		return r
	}
	start := time.Now()

	var notifications <-chan struct{}
	if eventMode {
		ch, unsubscribe, e := deviceguard.SubscribeChanges()
		if e == nil {
			notifications = ch
			defer unsubscribe()
		} else {
			diagnostic.EventSubscribeError = eno(e)
		}
	}
	for sample := 0; ; sample++ {
		if !eventMode && sample > 0 {
			seconds := []int{0, 3, 10}[sample]
			timer := time.NewTimer(time.Until(start.Add(time.Duration(seconds) * time.Second)))
			select {
			case <-ctx.Done():
				timer.Stop()
				r.Status = "TIME_LIMIT_NO_CHANGE"
				return r
			case <-timer.C:
			}
		}
		s := inventory(ctx)
		r.Samples = append(r.Samples, StartupSample{ElapsedMS: time.Since(start).Milliseconds(), Snapshot: s})
		readiness := startupReadinessFromSnapshot(s)
		diagnostic.add(startupDiagnosticSample(s, time.Since(start).Milliseconds(), readiness, configuredStartupEvidence{}, "IDENTITY_NOT_YET_RECHECKED"))
		if s.Error != "" || len(s.Devices) != 1 || !sameRootInstance(r.Before, s) || s.Devices[0].hub != target.hub || s.Devices[0].port != target.port || s.Devices[0].pid != target.pid {
			r.Status = "USB_TARGET_CHANGED_OR_UNREADABLE"
			return r
		}
		if !activeNCM(s.Devices[0].Configurations, s.Devices[0].CurrentConfiguration) {
			r.Status = "NCM_NO_LONGER_ACTIVE"
			return r
		}
		if ctx.Err() != nil {
			r.Status = "TIME_LIMIT_NO_CHANGE"
			return r
		}
		if !eventMode {
			if sample == 2 {
				diagnostic.ExitReason = "LEGACY_FINAL_TIMED_SAMPLE"
				break
			}
			continue
		}
		proof, reason := configuredStartupEvidence{}, "CONFIGURED_PROOF_NOT_REQUESTED"
		if readiness.settled() {
			reason = "GENERIC_PREDICATE_SETTLED"
		}
		if configuredDir != "" && mode != nil && !readiness.settled() {
			proof, reason = configuredStartupProof(ctx, configuredDir, *mode, s, readiness)
		}
		existingReady := false
		if configuredDir != "" && mode != nil && !readiness.settled() && !proof.ready() && len(consent) == 1 && consent[0] != nil && SimplifiedIPadNetworkConfigured() && IPadCandidateFeatures().PersistentGrouping && IPadCandidateFeatures().EventStartup {
			_, existing, existingReason := existingGroupingLiveProof(ctx, configuredDir, *mode, s, consent[0])
			if existingReason == "" {
				existingReady = true
				// Report live proof without setting receipt/registry ownership.
				proof = existing.CM
				proof.SameUSBRoot, proof.MappingVerified = existing.CurrentRoot, existing.Mapping
				reason = "EXISTING_OPERATIONAL_TOPOLOGY_PROVEN_NO_GROUPING_OWNERSHIP"
			} else if reason == "CONFIGURED_RECEIPT_UNAVAILABLE_OR_INVALID" {
				reason = existingReason
			}
		}
		diagnostic.FastPathReason = reason
		diagnostic.Samples[len(diagnostic.Samples)-1] = startupDiagnosticSample(s, time.Since(start).Milliseconds(), readiness, proof, reason)
		if readiness.settled() {
			diagnostic.ExitReason = "GENERIC_PREDICATE_SETTLED"
			break
		}
		if proof.ready() || existingReady {
			diagnostic.FastPathQualified = true
			diagnostic.ExitReason = reason
			break
		}
		if time.Since(start) >= 10*time.Second {
			diagnostic.ExitReason = "TEN_SECOND_CAP"
			break
		}
		// Notifications only request a fresh identity/readiness query. A 500ms
		// fallback bounds delayed/missing callbacks during this startup phase.
		timer := time.NewTimer(min(500*time.Millisecond, 10*time.Second-time.Since(start)))
		select {
		case <-ctx.Done():
			timer.Stop()
			r.Status = "TIME_LIMIT_NO_CHANGE"
			return r
		case <-notifications:
			timer.Stop()
		case <-timer.C:
		}
	}

	last := r.Samples[len(r.Samples)-1].Snapshot
	found := 0
	failed := false
	unknown := false
	for _, n := range last.Nodes {
		if !strings.Contains(strings.ToUpper(n.IDPrefix), "PID_"+target.PID) || !strings.EqualFold(n.Service, "UsbNcm") {
			continue
		}
		found++
		if grouptrial.NativeStartObserved(n.Problem, n.StateError, n.DevNodeStatus) {
			recordConnectionStage("native_ncm_started", "same_target_native_started_node_observed")
		}
		if n.StateError != "" {
			unknown = true
		} else if n.Problem != 0 {
			failed = true
		}
	}
	switch {
	case found == 0:
		r.Status = "NCM_PRESENT_NO_NATIVE_DRIVER_NODE"
	case unknown:
		r.Status = "NCM_DRIVER_STATE_UNAVAILABLE"
	case failed:
		r.Status = "NCM_PRESENT_NATIVE_DRIVER_START_FAILED"
	default:
		r.Status = "NCM_NATIVE_NODE_NO_PROBLEM_OBSERVED_NOT_NETWORK_PROOF"
	}
	return r
}
