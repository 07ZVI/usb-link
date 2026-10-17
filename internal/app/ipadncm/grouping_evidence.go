package ipadncm

import "sync"

type groupingEligibilityEvidence struct {
	Attempt              uint64   `json:"software_attempt"`
	Historical           bool     `json:"from_previous_software_attempt"`
	Status               string   `json:"status"`
	TopologyChecked      bool     `json:"topology_checked"`
	RootFound            bool     `json:"usbccgp_root_found"`
	RootProblem          uint32   `json:"root_problem"`
	RootStateReadable    bool     `json:"root_state_readable"`
	DriverVersion        string   `json:"root_driver_version"`
	DriverVersionMatches bool     `json:"driver_version_matches_486_0_0_0"`
	EnumeratorAbsent     bool     `json:"enumerator_class_verified_absent"`
	EnumeratorState      string   `json:"enumerator_class_state"`
	FailedControls       int      `json:"usbncm_problem10_readable_count"`
	UnboundData          int      `json:"mi03_mi05_unbound_problem28_readable_count"`
	FailedConditions     []string `json:"failed_conditions"`
}

type groupingEligibilityInput struct {
	RootFound                                                       bool
	RootProblem                                                     uint32
	RootStateError, DriverVersion, EnumeratorError, EnumeratorClass string
	FailedControls, UnboundData                                     int
}

var groupingEvidenceCache struct {
	sync.Mutex
	latest *groupingEligibilityEvidence
}

func currentSoftwareAttempt() uint64 {
	monitorDiagnostics.Lock()
	defer monitorDiagnostics.Unlock()
	return monitorDiagnostics.attempt
}

// Only dotted numeric versions are exported; unexpected registry text stays local.
func evidenceDriverVersion(value string) string {
	if value == "" {
		return "unavailable"
	}
	if len(value) > 32 {
		return "unexpected_format"
	}
	for _, c := range value {
		if c != '.' && (c < '0' || c > '9') {
			return "unexpected_format"
		}
	}
	return value
}

// Mirrors the observed predicates for explanation only. Admission continues to
// use the original checks against fresh native observations in Eligible.
func describeGroupingEligibility(in groupingEligibilityInput) groupingEligibilityEvidence {
	d := groupingEligibilityEvidence{TopologyChecked: true, RootFound: in.RootFound,
		RootProblem: in.RootProblem, RootStateReadable: in.RootFound && in.RootStateError == "",
		DriverVersion: evidenceDriverVersion(in.DriverVersion), DriverVersionMatches: in.DriverVersion == "486.0.0.0",
		EnumeratorAbsent: in.RootFound && in.EnumeratorError == "WIN32_2", FailedControls: in.FailedControls, UnboundData: in.UnboundData,
		EnumeratorState: "unavailable", FailedConditions: []string{}}
	if in.RootFound {
		switch {
		case in.EnumeratorError == "WIN32_2":
			d.EnumeratorState = "absent"
		case in.EnumeratorError != "":
			d.EnumeratorState = "read_failed"
		case in.EnumeratorClass == "020000":
			d.EnumeratorState = "grouping_value_present"
		default:
			d.EnumeratorState = "other_value_present"
		}
	}
	if !in.RootFound {
		d.FailedConditions = append(d.FailedConditions, "USBCCGP_ROOT_NOT_FOUND")
	} else {
		if in.RootProblem != 0 {
			d.FailedConditions = append(d.FailedConditions, "ROOT_HAS_PROBLEM")
		}
		if in.RootStateError != "" {
			d.FailedConditions = append(d.FailedConditions, "ROOT_STATE_UNREADABLE")
		}
		if !d.DriverVersionMatches {
			d.FailedConditions = append(d.FailedConditions, "ROOT_DRIVER_VERSION_MISMATCH")
		}
		if !d.EnumeratorAbsent {
			d.FailedConditions = append(d.FailedConditions, "ENUMERATOR_CLASS_NOT_VERIFIED_ABSENT")
		}
	}
	if in.FailedControls != 2 {
		d.FailedConditions = append(d.FailedConditions, "EXPECTED_TWO_FAILED_NCM_CONTROLS")
	}
	if in.UnboundData != 2 {
		d.FailedConditions = append(d.FailedConditions, "EXPECTED_TWO_UNBOUND_DATA_NODES")
	}
	return d
}

func recordGroupingEligibility(d groupingEligibilityEvidence, status string) {
	// All accepted values originate in fixed admission branches, never native errors.
	switch status {
	case "":
		d.Status = "ELIGIBLE"
	case "TARGET_CHANGED_OR_NCM_NOT_ACTIVE", "CURRENT_LAUNCH_IPAD_IDENTITY_REQUIRED", "DIAGNOSED_UNION_LAYOUT_REQUIRED", "DIAGNOSED_UNGROUPED_NATIVE_FAILURE_REQUIRED", "TARGET_WINDOWS_RESTART_REQUIRED", "ROOT_INSTANCE_CHANGED_SINCE_MODE_CHECK", "SOFTWARE_KEY_IDENTITY_UNAVAILABLE", "SOFTWARE_KEY_UNIQUENESS_QUERY_FAILED", "SOFTWARE_KEY_NOT_UNIQUE_OR_UNSUPPORTED", "TARGET_ROOT_OR_SOFTWARE_KEY_UNSUPPORTED", "TARGET_CHANGED_DURING_CONSENT", "ORIGINAL_GROUPING_VALUE_NOT_ABSENT":
		d.Status = status
	default:
		d.Status = "LATER_OWNERSHIP_CHECK_FAILED"
	}
	d.FailedConditions = append([]string{}, d.FailedConditions...)
	groupingEvidenceCache.Lock()
	groupingEvidenceCache.latest = &d
	groupingEvidenceCache.Unlock()
}

func latestGroupingEligibility() *groupingEligibilityEvidence {
	groupingEvidenceCache.Lock()
	defer groupingEvidenceCache.Unlock()
	if groupingEvidenceCache.latest == nil {
		return nil
	}
	d := *groupingEvidenceCache.latest
	d.FailedConditions = append([]string{}, d.FailedConditions...)
	return &d
}

type compactNativeStartEvidence struct {
	Attempt         uint64                    `json:"software_attempt"`
	Historical      bool                      `json:"from_previous_software_attempt"`
	Status          string                    `json:"status"`
	ExitReason      string                    `json:"exit_reason"`
	SampleCount     int                       `json:"sample_count"`
	SamplesOmitted  int                       `json:"samples_omitted"`
	Controls        int                       `json:"controls"`
	FailedControls  int                       `json:"failed_controls"`
	StartedControls int                       `json:"started_controls"`
	OrphanData      int                       `json:"orphan_data"`
	UngroupedRoot   bool                      `json:"ungrouped_root_confirmed"`
	FastPathReason  string                    `json:"configured_fast_path_reason"`
	ConfiguredProof configuredStartupEvidence `json:"configured_proof"`
}

func configuredStartupReasonCode(s string) string {
	switch s {
	case "":
		return "NOT_EVALUATED"
	case "CONFIGURED_CM_NODE_INSTANCE_CHANGED", "CONFIGURED_CM_NODE_INSTANCE_UNAVAILABLE", "CONFIGURED_CM_NODE_INSTANCE_UNREADABLE", "CONFIGURED_CM_NODE_ON_DIFFERENT_ROOT", "CONFIGURED_CM_PARENT_CHAIN_UNREADABLE", "CONFIGURED_NCM_MAPPING_NOT_UNIQUE_OPERATIONAL", "CONFIGURED_NCM_MAPPING_NOT_UNIQUE_OR_UNREADABLE", "CONFIGURED_OPERATIONAL_TOPOLOGY_PROVEN", "CONFIGURED_OWNERSHIP_CHANGED_DURING_MAPPING", "CONFIGURED_PROOF_NOT_ENABLED", "CONFIGURED_RECEIPT_UNAVAILABLE_OR_INVALID", "CONFIGURED_REGISTRY_NOT_OWNED", "CONFIGURED_ROOT_OR_MODE_IDENTITY_CHANGED", "OWNED_PRODUCT_PENDING_OPERATIONAL_TOPOLOGY_PROVEN", "CONFIGURED_CM_HARDWARE_ID_OR_CONTROL_LAYOUT_INVALID", "CONFIGURED_CM_NODE_RESTART_REQUIRED", "CONFIGURED_CM_NODE_ROOT_RELATIONSHIP_UNPROVEN", "CONFIGURED_CM_NODE_STATE_UNREADABLE", "CONFIGURED_CM_NO_STARTED_CONTROL", "CONFIGURED_CM_ROOT_NOT_HEALTHY", "CONFIGURED_PROOF_NOT_REQUESTED", "GENERIC_PREDICATE_SETTLED", "IDENTITY_NOT_YET_RECHECKED":
		return s
	default:
		return "OTHER"
	}
}

func nativeStartEvidenceCode(s string) string {
	switch s {
	case "INCOMPLETE", "NEED_ONE_READABLE_APPLE_USB_DEVICE", "USB_TARGET_CHANGED_BEFORE_START_CHECK", "CURRENT_MODE_IDENTITY_OR_ACTIVE_NCM_UNCONFIRMED", "IPAD_IDENTITY_UNCONFIRMED", "NCM_NOT_ACTIVE_NO_CHANGE", "TIME_LIMIT_NO_CHANGE", "USB_TARGET_CHANGED_OR_UNREADABLE", "NCM_NO_LONGER_ACTIVE", "NCM_PRESENT_NO_NATIVE_DRIVER_NODE", "NCM_DRIVER_STATE_UNAVAILABLE", "NCM_PRESENT_NATIVE_DRIVER_START_FAILED", "NCM_NATIVE_NODE_NO_PROBLEM_OBSERVED_NOT_NETWORK_PROOF", "GENERIC_PREDICATE_SETTLED", "LEGACY_FINAL_TIMED_SAMPLE", "TEN_SECOND_CAP", "CONFIGURED_OPERATIONAL_TOPOLOGY_PROVEN", "OWNED_PRODUCT_PENDING_OPERATIONAL_TOPOLOGY_PROVEN":
		return s
	default:
		return "OTHER"
	}
}

func compactNativeStart(d StartupReadinessDiagnostic) *compactNativeStartEvidence {
	e := &compactNativeStartEvidence{Attempt: d.Attempt, Status: nativeStartEvidenceCode(d.Status), ExitReason: nativeStartEvidenceCode(d.ExitReason), SampleCount: d.SampleCount, SamplesOmitted: d.SamplesOmitted, FastPathReason: configuredStartupReasonCode(d.FastPathReason)}
	if len(d.Samples) > 0 {
		s := d.Samples[len(d.Samples)-1]
		e.Controls, e.FailedControls, e.StartedControls, e.OrphanData, e.UngroupedRoot = s.Controls, s.FailedControls, s.StartedControls, s.OrphanData, s.UngroupedRoot
		e.ConfiguredProof = s.ConfiguredProof
		if s.FastPathReason != "" {
			e.FastPathReason = configuredStartupReasonCode(s.FastPathReason)
		}
	}
	return e
}
