package ipadncm

// A live network target is deliberately not a grouping journal: it contains no
// claim about the original registry value and cannot authorize its restoration.
type existingNetworkTarget struct{ root, driver string }

type existingGroupingAdmission struct {
	Consent, CurrentRoot, Driver, ReceiptsAbsent, Mapping, ContextActive bool
	CM                                                                   configuredStartupEvidence
}

func (e existingGroupingAdmission) failure() string {
	switch {
	case !e.ContextActive:
		return "EXISTING_GROUPING_CONTEXT_CANCELLED"
	case !e.Consent:
		return "EXISTING_GROUPING_CURRENT_CONSENT_REQUIRED"
	case !e.CurrentRoot:
		return "EXISTING_GROUPING_CURRENT_ROOT_REQUIRED"
	case !e.ReceiptsAbsent:
		return "EXISTING_GROUPING_RECEIPT_STATE_CHANGED"
	case !e.Driver:
		return "EXISTING_GROUPING_OFFICIAL_DRIVER_UNPROVEN"
	}
	if reason := configuredCMFailureReason(e.CM); reason != "" {
		return reason
	}
	if e.CM.StartedControls > 2 {
		return "EXISTING_GROUPING_CONTROL_COUNT_INVALID"
	}
	if !e.Mapping {
		return "EXISTING_GROUPING_UNIQUE_OPERATIONAL_MAPPING_REQUIRED"
	}
	return ""
}
