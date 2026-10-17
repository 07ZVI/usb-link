package ipadncm

const connectionEvidenceEventLimit = 12

type connectionEvidenceEvent struct {
	Attempt   uint64 `json:"attempt"`
	Stage     string `json:"stage"`
	ElapsedMS int64  `json:"ms_since_software_attempt_not_physical_insertion"`
}

// Only cached, bounded diagnostics leave this boundary. Native errors, device
// identities and credentials are never exported.
type IPadConnectionEvidence struct {
	Schema                        int                          `json:"schema"`
	State                         string                       `json:"state"`
	SessionActive                 bool                         `json:"session_active"`
	HasError                      bool                         `json:"has_error"`
	DHCPStarted                   bool                         `json:"dhcp_started"`
	DHCPACKs                      uint32                       `json:"dhcp_acks"`
	PeerVerified                  bool                         `json:"peer_verified"`
	HTTPVerified                  bool                         `json:"http_verified"`
	SunshineTCPObserved           bool                         `json:"sunshine_tcp_observed"`
	ApplicationEvidenceHistorical bool                         `json:"application_evidence_may_be_previous_session"`
	Attempts                      uint64                       `json:"software_connection_attempts_all_devices"`
	AutomaticRetries              uint64                       `json:"automatic_retry_attempts"`
	ManualRetries                 uint64                       `json:"manual_retry_requests"`
	Events                        []connectionEvidenceEvent    `json:"recent_ipad_operation_events"`
	RelevantEventsOmitted         int                          `json:"older_matching_events_omitted"`
	SourceEventsOmitted           uint64                       `json:"source_buffer_events_omitted_all_stages"`
	GroupingEligibility           *groupingEligibilityEvidence `json:"latest_grouping_eligibility,omitempty"`
	GroupingReceipt               *GroupingReceiptDiagnostic   `json:"grouping_receipt,omitempty"`
	NativeStart                   *compactNativeStartEvidence  `json:"latest_native_start,omitempty"`
}

func CompactConnectionEvidence() IPadConnectionEvidence {
	r := ApplicationResult{DeviceKind: "iPad", Status: "MONITOR_WAITING"}
	if state := deviceMonitor("iPad"); state != nil {
		r = state.snapshot()
		r.DeviceKind = "iPad"
	}
	e := compactConnectionEvidence(r, ConnectionMonitorDiagnostics())
	e.GroupingReceipt = GroupingReceiptDiagnostics()
	if e.GroupingReceipt != nil {
		e.GroupingReceipt.Historical = e.GroupingReceipt.Attempt != e.Attempts
	}
	e.GroupingEligibility = latestGroupingEligibility()
	if e.GroupingEligibility != nil {
		e.GroupingEligibility.Historical = e.GroupingEligibility.Attempt != e.Attempts
	}
	if history := StartupReadinessDiagnostics(); len(history) > 0 {
		e.NativeStart = compactNativeStart(history[len(history)-1])
		e.NativeStart.Historical = e.NativeStart.Attempt != e.Attempts
	}
	return e
}

func compactConnectionEvidence(r ApplicationResult, monitor MonitorDiagnostics) IPadConnectionEvidence {
	active := sessionRunning(r)
	e := IPadConnectionEvidence{
		Schema: 1, State: desktopConnectionState(r, false), SessionActive: active, HasError: r.Error != "",
		DHCPStarted: r.DHCPStarted, DHCPACKs: r.DHCPACKs, PeerVerified: r.PeerIPv4NeighborVerified,
		HTTPVerified: r.HTTPVerified, SunshineTCPObserved: r.SunshineClientTCPObserved,
		ApplicationEvidenceHistorical: !active, Attempts: monitor.Attempts,
		AutomaticRetries: monitor.AutomaticRetries, ManualRetries: monitor.ManualRetries,
		Events: make([]connectionEvidenceEvent, 0, connectionEvidenceEventLimit), SourceEventsOmitted: monitor.DroppedConnectionEvents,
	}
	for _, event := range monitor.ConnectionTrace {
		switch event.Stage {
		case "usb_mode_switch_begin", "usb_mode_switch_end", "device_restart_begin", "device_restart_end", "grouping_write_begin", "grouping_write_end", "grouping_restore_begin", "grouping_restore_end":
		default:
			continue
		}
		if len(e.Events) == connectionEvidenceEventLimit {
			e.Events = e.Events[1:]
			e.RelevantEventsOmitted++
		}
		e.Events = append(e.Events, connectionEvidenceEvent{event.Attempt, event.Stage, event.ElapsedMS})
	}
	return e
}
