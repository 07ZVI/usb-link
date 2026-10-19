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
