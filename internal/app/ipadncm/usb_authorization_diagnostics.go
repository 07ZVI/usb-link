package ipadncm

type usbAuthorizationReadback struct {
	USB                   USBDescriptorRecheckDiagnostic `json:"usb"`
	ExactRootPresent      bool                           `json:"exact_root_present_not_authorization"`
	NetworkLayoutEligible bool                           `json:"network_layout_eligible_not_authorization"`
	CurrentConfiguration  byte                           `json:"current_configuration"`
	RejectionCodesOmitted int                            `json:"rejection_codes_omitted"`
	ReadCodesOmitted      int                            `json:"connection_read_codes_omitted"`
}

// Only summaries of reads already required by Allow are retained. A failure
// must not trigger another descriptor request, retry or consent decision.
type usbAuthorizationFailureDiagnostic struct {
	Attempt       uint64                    `json:"software_attempt"`
	Phase         string                    `json:"phase"`
	ConsentStatus string                    `json:"consent_status"`
	ContextActive bool                      `json:"context_active"`
	ElapsedMS     int64                     `json:"elapsed_ms"`
	ReadCount     int                       `json:"existing_snapshot_reads"`
	Initial       *usbAuthorizationReadback `json:"initial_readback,omitempty"`
	Latest        *usbAuthorizationReadback `json:"latest_readback,omitempty"`
}

func sanitizedAuthorizationFailure(d usbAuthorizationFailureDiagnostic) usbAuthorizationFailureDiagnostic {
	d.Phase = "authorization_failed"
	switch d.ConsentStatus {
	case "INITIAL_CONFIGURATION_CANCELLED", "INITIAL_CONFIGURATION_TIMEOUT", "INITIAL_CONFIGURATION_TARGET_CHANGED_OR_UNREADABLE", "INITIAL_CONFIGURATION_UNSUPPORTED", "INITIAL_CONFIGURATION_FULL_PROOF_FAILED":
	default:
		d.ConsentStatus = boundedUSBRejectionCode(d.ConsentStatus)
	}
	copyReadback := func(r *usbAuthorizationReadback) *usbAuthorizationReadback {
		if r == nil {
			return nil
		}
		v := *r
		// Keep both end snapshots within the archive's single-record bound.
		if len(v.USB.RejectionCodes) > 8 {
			v.RejectionCodesOmitted += len(v.USB.RejectionCodes) - 8
			v.USB.RejectionCodes = v.USB.RejectionCodes[:8]
		}
		if len(v.USB.ConnectionReadErrorCodes) > 8 {
			v.ReadCodesOmitted += len(v.USB.ConnectionReadErrorCodes) - 8
			v.USB.ConnectionReadErrorCodes = v.USB.ConnectionReadErrorCodes[:8]
		}
		v.USB = sanitizeUSBDescriptorRecheck(v.USB)
		return &v
	}
	d.Initial, d.Latest = copyReadback(d.Initial), copyReadback(d.Latest)
	return d
}
