package ipadncm

import (
	"strings"
	"sync"
	"time"
)

// Classification of failures that end an attempt in MONITOR_PAUSED. A failed
// authorization used to collapse into one fixed code that never retries, so a
// readiness race right after arrival looked exactly like a declined prompt.
// Nothing here grants a permission: a retry repeats the complete authorization
// (fresh reads, security inventory, exact attachment, saved or interactive
// consent) and is still bounded by autoRetryBudget and sameAttachmentGate.

// Retryable authorization failures carry this prefix; the detail after it is
// the original consent status, kept for diagnostics.
const authorizationTransientPrefix = "USB_AUTHORIZATION_TRANSIENT"

func authorizationTransientError(status string) string {
	return authorizationTransientPrefix + ": " + status
}
func isAuthorizationTransientError(reason string) bool {
	return reason == authorizationTransientPrefix || strings.HasPrefix(reason, authorizationTransientPrefix+":")
}

// What a read of the iPad's USB state looked like when the preflight failed.
type preflightFacts struct {
	SnapshotError  string
	DeviceCount    int
	RootUnique     bool
	DeviceErrors   []string
	SerialStatus   string
	ProductStatus  string
	Configuration  byte
	DescriptorRead bool // The device descriptor was read, so Configuration is meaningful.
}

func usbStringReadFailure(status string) bool {
	return strings.HasPrefix(status, "USB_STRING_READ_") || strings.HasPrefix(status, "USB_LANGID_READ_")
}

// Per-error classification. Only I/O style read failures are transient; any
// code that reports a mismatch, a malformed descriptor or an unexpected layout
// keeps the pause.
func transientDeviceError(code string, f preflightFacts) bool {
	switch code {
	case "USB_IDENTITY_LANGID_READ_FAILED", "USB_CONNECTION_CHANGED_DURING_DESCRIPTOR_READ", "USB_DESCRIPTOR_NATIVE_ROOT_UNREADABLE":
		return true
	case "USB_SERIAL_OR_PRODUCT_DESCRIPTOR_UNCONFIRMED":
		okOrRead := func(s string) bool { return s == "USB_STRING_VERIFIED" || usbStringReadFailure(s) }
		return (usbStringReadFailure(f.SerialStatus) || usbStringReadFailure(f.ProductStatus)) && okOrRead(f.SerialStatus) && okOrRead(f.ProductStatus)
	}
	if strings.HasPrefix(code, "CONFIG_") {
		return strings.HasSuffix(code, "_HEADER_UNAVAILABLE") || strings.Contains(code, "_READ_")
	}
	return false
}

// True when the failed preflight is a not-yet-ready or unreadable observation
// rather than a verdict about the device. Identity conflicts (serial/root
// mismatch, ambiguous root, binding failure), malformed descriptors and a
// settled non-initial configuration or layout are never transient.
func preflightFailureTransient(f preflightFacts) bool {
	if f.SnapshotError != "" || f.DeviceCount != 1 {
		return true
	}
	if len(f.DeviceErrors) > 0 {
		for _, e := range f.DeviceErrors {
			if !transientDeviceError(e, f) {
				return false
			}
		}
		return true
	}
	if !f.RootUnique {
		return true
	}
	return f.DescriptorRead && f.Configuration == 0
}

// Initial-configuration wait results. Cancellation, an unsupported settled
// configuration and everything else keep the pause; a timeout or an unreadable
// target is a readiness race. A failed full proof is classified from the facts
// of the snapshot it produced.
func initialConfigurationTransient(state string, full preflightFacts) bool {
	switch state {
	case "INITIAL_CONFIGURATION_TIMEOUT", "INITIAL_CONFIGURATION_TARGET_CHANGED_OR_UNREADABLE":
		return true
	case "INITIAL_CONFIGURATION_FULL_PROOF_FAILED":
		return preflightFailureTransient(full)
	}
	return false
}

// Mode-phase statuses that are returned before any mode request is sent and
// describe an unready or unreadable device, not a decision or a mismatch.
func transientModeStatus(status string) bool {
	switch status {
	case "INVENTORY_INCOMPLETE", "NEED_ONE_APPLE_MOBILE_DEVICE", "NETWORK_ONLY_USB_LAYOUT_NOT_READY",
		"USB_TARGET_CHANGED_NO_CONTROL_REQUEST", "CONTROL_ACCESS_BLOCKED_NOT_A_SUPPORT_VERDICT":
		return true
	}
	return false
}

// These mode statuses are reported whenever the consent callback returns
// false, including a transient re-verification failure after the first grant.
func modeStatusFromConsentCallback(status string) bool {
	return status == "MODE_CHANGE_DECLINED" || status == "MODE_CHANGE_DECLINED_OR_CANCELLED"
}

// Last outcome of ConnectionAuthorization.Allow, kept for retry classification
// and for the exported diagnostics.
type authorizationOutcome struct {
	Status      string   `json:"consent_status"`
	Transient   bool     `json:"retryable_readiness_failure"`
	Interactive bool     `json:"consent_prompt_shown"`
	Details     []string `json:"read_error_codes,omitempty"`
}

var lastAuthorization struct {
	sync.Mutex
	v authorizationOutcome
}

func recordAuthorizationOutcome(o authorizationOutcome) {
	if len(o.Details) > 4 {
		o.Details = o.Details[:4]
	}
	lastAuthorization.Lock()
	lastAuthorization.v = o
	lastAuthorization.Unlock()
}
func authorizationOutcomeSnapshot() authorizationOutcome {
	lastAuthorization.Lock()
	defer lastAuthorization.Unlock()
	o := lastAuthorization.v
	o.Details = append([]string(nil), o.Details...)
	return o
}

// The failure to report for an authorization that returned false. Anything not
// positively classified as a readiness race, and any failure after a consent
// prompt was shown, keeps the original code.
func authorizationFailureError(o authorizationOutcome, fallback string) string {
	if o.Transient && !o.Interactive && o.Status != "" {
		return authorizationTransientError(o.Status)
	}
	return fallback
}

// A mode status that merely relays a false consent callback becomes a
// readiness failure only when the last authorization said so.
func modeFailureError(status string, o authorizationOutcome) string {
	if modeStatusFromConsentCallback(status) && o.Transient && !o.Interactive && o.Status != "" {
		return authorizationTransientError(o.Status)
	}
	return status
}

// Bounded failure history for the exported diagnostics. The first failure of
// an attachment is flagged so a first-attempt pause is not lost when later
// retries succeed.
type attemptFailureRecord struct {
	SoftwareAttempt   uint64   `json:"software_attempt"`
	Code              string   `json:"code"`
	ConsentStatus     string   `json:"consent_status,omitempty"`
	ReadErrorCodes    []string `json:"read_error_codes,omitempty"`
	FirstOfAttachment bool     `json:"first_of_attachment"`
	ApplicationRan    bool     `json:"application_ran"`
	AutoRetryEligible bool     `json:"auto_retry_eligible"`
	UTC               string   `json:"utc"`
}
type attemptFailureLog struct {
	mu      sync.Mutex
	entries []attemptFailureRecord
	fresh   bool
}

func newAttemptFailureLog() *attemptFailureLog { return &attemptFailureLog{fresh: true} }

func (l *attemptFailureLog) record(r attemptFailureRecord, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r.FirstOfAttachment, l.fresh = l.fresh, false
	r.UTC = now.UTC().Format(time.RFC3339)
	if len(r.ReadErrorCodes) > 4 {
		r.ReadErrorCodes = r.ReadErrorCodes[:4]
	}
	if len(r.Code) > 160 {
		r.Code = r.Code[:160]
	}
	if len(l.entries) == 4 {
		// Keep the first-of-attachment entry visible while it is the oldest.
		keep := 0
		if l.entries[0].FirstOfAttachment {
			keep = 1
		}
		l.entries = append(l.entries[:keep], l.entries[keep+1:]...)
	}
	l.entries = append(l.entries, r)
}
func (l *attemptFailureLog) newAttachment() {
	l.mu.Lock()
	l.fresh = true
	l.mu.Unlock()
}
func (l *attemptFailureLog) snapshot() []attemptFailureRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]attemptFailureRecord(nil), l.entries...)
}

var attemptFailures = newAttemptFailureLog()

// Compact, always-exported view for the trust-prompt investigation. It adds
// no new reads: every field is state the program already holds.
type trustPromptDiagnostic struct {
	KnownPhotoInstances      int                    `json:"known_photo_instances"`
	KnownLearnedThisRun      int                    `json:"known_learned_this_run"`
	KnownCode                string                 `json:"known_code,omitempty"`
	AppliedBeforeModeRequest bool                   `json:"applied_before_mode_request"`
	BeforeModeRequestRan     bool                   `json:"before_mode_request_ran"`
	BeforeModeRequestKnown   int                    `json:"before_mode_request_known"`
	BeforeModeRequestCode    string                 `json:"before_mode_request_code,omitempty"`
	PhotoIsolationPhase      string                 `json:"photo_isolation_phase"`
	PhotoIsolationEffective  bool                   `json:"photo_isolation_effective"`
	PhotoFirstSightings      []localPhotoSighting   `json:"photo_first_sightings"`
	LastAuthorization        authorizationOutcome   `json:"last_authorization"`
	AttemptFailures          []attemptFailureRecord `json:"recent_attempt_failures"`
}

func trustPromptDiagnosticFrom(p localPhotoStatus, o authorizationOutcome, f []attemptFailureRecord) trustPromptDiagnostic {
	if f == nil {
		f = []attemptFailureRecord{}
	}
	return trustPromptDiagnostic{
		KnownPhotoInstances: p.KnownNodes, KnownLearnedThisRun: p.KnownLearned, KnownCode: p.KnownCode,
		AppliedBeforeModeRequest: p.PreModeApplied, BeforeModeRequestRan: p.PreModeRan,
		BeforeModeRequestKnown: p.PreModeKnown, BeforeModeRequestCode: p.PreModeCode,
		PhotoIsolationPhase: p.Phase, PhotoIsolationEffective: p.Effective, PhotoFirstSightings: append([]localPhotoSighting{}, p.Sightings...),
		LastAuthorization: o, AttemptFailures: f,
	}
}
