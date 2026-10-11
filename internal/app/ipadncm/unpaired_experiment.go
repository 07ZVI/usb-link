package ipadncm

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// Metadata contains no filename, descriptor serial, path or pairing content.
// A digest binds a fresh metadata observation; the suffix is display only.
type UnpairedPairMetadata struct {
	OriginalAbsent  bool   `json:"original_absent"`
	BackupPresent   bool   `json:"backup_present_metadata_only"`
	USBSerialSuffix string `json:"usb_serial_suffix"`
	USBSerialSHA256 string `json:"usb_serial_sha256"`
}
type UnpairedMetadataObservation struct {
	Phase          string `json:"phase"`
	UTC            string `json:"utc"`
	OriginalAbsent bool   `json:"original_absent"`
	BackupPresent  bool   `json:"backup_present_metadata_only"`
}
type UnpairedExperimentEvent struct {
	Kind         string `json:"kind"`
	UTC          string `json:"utc"`
	AfterReplied bool   `json:"after_operator_recorded_reply"`
}
type UnpairedExperimentStatus struct {
	State                      string                        `json:"state"`
	Pending                    bool                          `json:"pending"`
	Busy                       bool                          `json:"busy"`
	Blocked                    bool                          `json:"blocked"`
	PreparedUTC                string                        `json:"prepared_utc,omitempty"`
	ExpiresUTC                 string                        `json:"expires_utc,omitempty"`
	BoundUTC                   string                        `json:"bound_utc,omitempty"`
	RepliedUTC                 string                        `json:"operator_recorded_reply_utc,omitempty"`
	SerialSHA256               string                        `json:"usb_serial_sha256,omitempty"`
	SerialSuffix               string                        `json:"usb_serial_suffix,omitempty"`
	Attempts                   int                           `json:"attempts"`
	FirstFailure               string                        `json:"first_failure,omitempty"`
	CompletionReason           string                        `json:"completion_reason,omitempty"`
	RestoreProblem             string                        `json:"restore_problem,omitempty"`
	LastAttempt                *UnpairedAttemptDiagnostic    `json:"last_attempt_bounded_diagnostic,omitempty"`
	DiagnosticStartupHeld      bool                          `json:"diagnostic_startup_held"`
	Problem                    string                        `json:"problem,omitempty"`
	RestoreVerified            bool                          `json:"recorded_state_restore_verified"`
	Metadata                   []UnpairedMetadataObservation `json:"metadata_observations,omitempty"`
	Events                     []UnpairedExperimentEvent     `json:"events,omitempty"`
	DHCPRequestsBeforeReply    uint64                        `json:"validated_dhcp_requests_before_recorded_reply"`
	DHCPRequestsAfterReply     uint64                        `json:"validated_dhcp_requests_after_recorded_reply"`
	ARPCaptureSupported        bool                          `json:"arp_packet_capture_supported"`
	GeneralUDPCaptureSupported bool                          `json:"general_udp_packet_capture_supported"`
}

var unpairedFeatureLease atomic.Bool
var unpairedDiagnosticStartupHoldState atomic.Bool

// This model never grants consent, creates identities, imports dual-mode proof,
// or interprets suffixes as authority. Its one scope is established by native
// admission after the existing user-consent boundary.
type unpairedExperimentModel struct {
	status  UnpairedExperimentStatus
	expires time.Time
	root    string // private native root, never serialized
}

func (m *unpairedExperimentModel) live(now time.Time) bool {
	return !m.status.Blocked && !m.status.Pending && !m.status.Busy && now.Before(m.expires) && (m.status.State == "PREPARED" || m.status.State == "BOUND")
}
func validUnpairedMetadata(v UnpairedPairMetadata, digest string) bool {
	if !v.OriginalAbsent || !v.BackupPresent || len(digest) != 64 || v.USBSerialSHA256 != digest || len(v.USBSerialSuffix) != 4 {
		return false
	}
	for _, s := range []string{digest, v.USBSerialSuffix} {
		for _, c := range s {
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return false
			}
		}
	}
	return true
}
func (m *unpairedExperimentModel) bind(now time.Time, root, digest string, v UnpairedPairMetadata) error {
	if !m.live(now) || m.status.State != "PREPARED" || m.status.Attempts != 0 || root == "" || !validUnpairedMetadata(v, digest) {
		return fmt.Errorf("unpaired experiment scope or metadata unproven")
	}
	m.root = root
	m.status.State = "BOUND"
	m.status.Attempts = 1
	m.status.BoundUTC = now.UTC().Format(time.RFC3339Nano)
	m.status.SerialSHA256 = digest
	m.status.SerialSuffix = v.USBSerialSuffix
	m.metadata(now, "after_consent", v)
	return nil
}
func (m *unpairedExperimentModel) metadata(now time.Time, phase string, v UnpairedPairMetadata) {
	if len(m.status.Metadata) >= 8 {
		m.status.Metadata = m.status.Metadata[1:]
	}
	m.status.Metadata = append(m.status.Metadata, UnpairedMetadataObservation{phase, now.UTC().Format(time.RFC3339Nano), v.OriginalAbsent, v.BackupPresent})
}
func (m *unpairedExperimentModel) event(now time.Time, kind string) {
	if m.status.State != "BOUND" || m.status.Blocked || !now.Before(m.expires) {
		return
	}
	after := m.status.RepliedUTC != ""
	if kind == "dhcp_discover" || kind == "dhcp_request" || kind == "dhcp_decline" || kind == "dhcp_other" {
		if after {
			m.status.DHCPRequestsAfterReply++
		} else {
			m.status.DHCPRequestsBeforeReply++
		}
	}
	// Keep first occurrence of each event on each side of the user's reply;
	// counts retain repeated DHCP requests without an unbounded packet log.
	for _, e := range m.status.Events {
		if e.Kind == kind && e.AfterReplied == after {
			return
		}
	}
	if len(m.status.Events) < 32 {
		m.status.Events = append(m.status.Events, UnpairedExperimentEvent{kind, now.UTC().Format(time.RFC3339Nano), after})
	}
}
func (m *unpairedExperimentModel) stop(reason string) {
	m.status.Pending = true
	m.status.State = "FINISH_PENDING"
	if reason == "ONE_ATTEMPT_COMPLETE" || reason == "" {
		m.status.CompletionReason = reason
		if m.status.Problem == "" {
			m.status.Problem = reason
		}
		return
	}
	if m.status.FirstFailure == "" {
		m.status.FirstFailure = reason
	}
	m.status.Problem = m.status.FirstFailure
}
func (m *unpairedExperimentModel) restored(err error) {
	m.status.Pending = false
	m.status.Busy = false
	m.status.Blocked = err != nil
	m.status.RestoreVerified = err == nil
	if err != nil {
		m.status.State = "RESTORE_PENDING"
		m.status.RestoreProblem = unpairedPublicProblem(err)
		if m.status.FirstFailure == "" {
			m.status.FirstFailure = m.status.RestoreProblem
		}
		m.status.Problem = m.status.FirstFailure
	} else {
		m.status.State = "FINISHED"
		m.status.RestoreProblem = ""
	}
}

func (m *unpairedExperimentModel) reject(err error) {
	m.status.Pending = false
	m.status.Busy = false
	m.status.Blocked = false
	m.status.State = "REJECTED"
	m.status.FirstFailure = "PREPARATION_REJECTED: " + unpairedPublicProblem(err)
	m.status.Problem = m.status.FirstFailure
	m.status.RestoreVerified = false
}
func unpairedRestoreOwned(cleanupSafe, borrowed bool, restore func() error) error {
	if !cleanupSafe {
		return fmt.Errorf("unpaired session cleanup unresolved; originals retained")
	}
	if borrowed {
		return restore()
	}
	return nil
}
func unpairedExpectedServicePolicy(readable bool, originalState, originalStart, receiptState, receiptStart, currentState, currentStart uint32) bool {
	return readable && (originalState == 1 || originalState == 4) && (originalStart == 2 || originalStart == 3) && receiptState == originalState && receiptStart == originalStart && currentState == 1 && currentStart == networkOnlyServiceStartType(originalStart)
}

func unpairedPublicProblem(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 160 || strings.ContainsAny(s, "\\/\r\n") {
		return "NATIVE_OPERATION_UNREADABLE"
	}
	return s
}

// Only static publisher-owned startup code calls this; no RPC or saved setting
// exposes it. A prepared explicit experiment is still allowed its one attempt.
func ConfigureUnpairedDiagnosticStartupHold(enabled bool) {
	unpairedDiagnosticStartupHoldState.Store(enabled)
}
func unpairedDiagnosticShouldHold(enabled bool, m unpairedExperimentModel, now time.Time) bool {
	return enabled && !(m.status.State == "PREPARED" && m.live(now))
}
func diagnosticCode(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > 96 {
		return "NON_CODE_DETAIL_REDACTED"
	}
	for _, c := range s {
		if c != '_' && c != '-' && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return "NON_CODE_DETAIL_REDACTED"
		}
	}
	return s
}

// This is a whitelist, not serialization of ConnectionAuthorization or its
// optional legacy pairing proof. All error strings must be constant codes.
type UnpairedAttemptDiagnostic struct {
	Stage                 string                        `json:"stage_code,omitempty"`
	Error                 string                        `json:"error_code,omitempty"`
	ConsentStatus         string                        `json:"usb_consent_status_code,omitempty"`
	MetadataError         string                        `json:"metadata_error_code,omitempty"`
	SecurityFailure       string                        `json:"security_failure_code,omitempty"`
	AllowedThisConnection bool                          `json:"allowed_this_connection_recorded"`
	USBInfoMatched        bool                          `json:"usb_information_matched"`
	InitialDescriptor     *UnpairedDescriptorDiagnostic `json:"initial_descriptor_bounded,omitempty"`
}
type UnpairedDescriptorDiagnostic struct {
	DeviceCount          int                            `json:"device_count_capped_at_64"`
	Error                string                         `json:"inventory_error_code,omitempty"`
	Eligible             bool                           `json:"network_layout_and_root_eligible"`
	Verified             bool                           `json:"descriptor_identity_verified"`
	CurrentConfiguration byte                           `json:"current_configuration"`
	SerialSHA256         string                         `json:"descriptor_serial_sha256,omitempty"`
	SerialStatus         string                         `json:"serial_read_status_code,omitempty"`
	ProductStatus        string                         `json:"product_read_status_code,omitempty"`
	SerialFailureShape   *USBIdentityStringFailureShape `json:"serial_failure_aggregates_only,omitempty"`
	Errors               []string                       `json:"usb_error_codes,omitempty"`
}
type UnpairedExperimentPreflight struct {
	ObservedUTC           string                        `json:"observed_utc"`
	DiagnosticStartupHeld bool                          `json:"diagnostic_startup_held"`
	Before                UnpairedDescriptorDiagnostic  `json:"before"`
	After                 *UnpairedDescriptorDiagnostic `json:"after,omitempty"`
	AttachmentStable      bool                          `json:"fresh_attachment_stable"`
	OfficialRootHealthy   bool                          `json:"official_root_binding_healthy"`
	NativeRootHealthy     bool                          `json:"native_root_healthy"`
	DriverHashVerified    bool                          `json:"pinned_control_driver_hash_verified"`
	Metadata              *UnpairedPairMetadata         `json:"fresh_pair_file_metadata_snapshot,omitempty"`
	MetadataError         string                        `json:"metadata_error_code,omitempty"`
	Error                 string                        `json:"error_code,omitempty"`
	ConsentGranted        bool                          `json:"consent_granted_by_this_readback"`
	ModeChanged           bool                          `json:"mode_changed_by_this_readback"`
	ServiceChanged        bool                          `json:"service_changed_by_this_readback"`
}

func unpairedMetadataFailureCode(problem string) string {
	const prefix = "PAIR_METADATA_CHECK: "
	if !strings.HasPrefix(problem, prefix) {
		return ""
	}
	return diagnosticCode(strings.TrimPrefix(problem, prefix))
}
func diagnosticDigest(s string) string {
	if len(s) != 64 {
		return ""
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return ""
		}
	}
	return s
}
