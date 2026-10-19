package ipadncm

import "time"

// The origin is the software connection attempt, not physical cable insertion.
// Omitted stages remain unknown. DHCP ACK and a local server probe are not proof
// that the iPad applied an address or reached Sunshine.
type ConnectionEvent struct {
	Attempt   uint64 `json:"attempt"`
	UTC       string `json:"event_utc,omitempty"`
	ElapsedMS int64  `json:"ms_since_software_attempt_not_physical_insertion"`
	Stage     string `json:"stage"`
	Evidence  string `json:"evidence"`
}

func validConnectionStage(stage string) bool {
	switch stage {
	case "usb_mode_switch_begin", "usb_mode_switch_end", "usb_control_open_begin", "usb_control_open_end", "usb_get_mode_begin", "usb_get_mode_end", "usb_set_mode_request_begin", "usb_set_mode_request_end":
		return true
	case "usb_enumerated", "grouping_applied", "native_ncm_started", "adapter_mapped", "ip_configured", "dhcp_ack_sent", "ipv4_neighbor_verified", "sunshine_peer_tcp_observed", "native_start_check_begin", "native_start_check_end", "passive_network_observation_begin", "passive_network_observation_end", "grouping_write_begin", "grouping_write_end", "device_restart_begin", "device_restart_end", "grouping_restore_begin", "grouping_restore_end", "apple_service_lease_begin", "apple_service_lease_end", "application_firewall_begin", "application_firewall_end", "core_permissions_begin", "core_permissions_end", "sunshine_local_probe_begin", "sunshine_local_probe_end", "dhcp_listener_started", "optional_application_services_ready", "application_permission_batch_begin", "application_permission_batch_end":
		return true
	}
	return false
}
func (m *monitorDiagnosticCounter) stage(stage, evidence string, once bool) {
	m.stageFor(0, stage, evidence, once)
}
func (m *monitorDiagnosticCounter) stageFor(expectedAttempt uint64, stage, evidence string, once bool) {
	if !validConnectionStage(stage) {
		return
	}
	m.Lock()
	defer func() {
		m.Unlock()
	}()
	if m.deviceKind != "iPad" || m.attemptStarted.IsZero() {
		return
	}
	if expectedAttempt != 0 && expectedAttempt != m.attempt {
		return
	}
	if once {
		for i := len(m.r.ConnectionTrace) - 1; i >= 0; i-- {
			e := m.r.ConnectionTrace[i]
			if e.Attempt != m.attempt {
				break
			}
			if e.Stage == stage {
				return
			}
		}
	}
	if len(evidence) > 128 {
		evidence = evidence[:128]
	}
	if len(m.r.ConnectionTrace) == 128 {
		m.r.ConnectionTrace = m.r.ConnectionTrace[1:]
		m.r.DroppedConnectionEvents++
	}
	now := time.Now()
	event := ConnectionEvent{Attempt: m.attempt, UTC: now.UTC().Format(time.RFC3339Nano), ElapsedMS: now.Sub(m.attemptStarted).Milliseconds(), Stage: stage, Evidence: evidence}
	m.r.ConnectionTrace = append(m.r.ConnectionTrace, event)
}
func recordConnectionStage(stage, evidence string) { monitorDiagnostics.stage(stage, evidence, true) }

// RecordConnectionOperation records a known action window for correlation with
// device notifications. It does not claim that the action caused a notice.
func RecordConnectionOperation(operation string) func() {
	switch operation {
	case "usb_control_open", "usb_get_mode", "usb_mode_switch", "usb_set_mode_request":
	case "grouping_write", "device_restart", "grouping_restore", "apple_service_lease", "passive_network_observation", "native_start_check", "application_firewall", "core_permissions", "sunshine_local_probe", "application_permission_batch":
	default:
		return func() {}
	}
	m := monitorDiagnostics
	m.Lock()
	attempt := m.attempt
	kind := m.deviceKind
	if kind != "iPad" {
		m.Unlock()
		return func() {}
	}
	previous := m.operation
	previousActive := m.operationActive
	m.operation = operation
	m.operationActive = true
	m.operationAt = time.Now()
	m.Unlock()
	m.stageFor(attempt, operation+"_begin", "own_operation_started", false)
	return func() {
		m.Lock()
		same := m.attempt == attempt
		if same {
			m.operation = operation
			m.operationActive = false
			m.operationAt = time.Now()
			if previousActive {
				m.operation = previous
				m.operationActive = true
			}
		}
		m.Unlock()
		if same {
			m.stageFor(attempt, operation+"_end", "own_operation_returned; result in existing diagnostics", false)
		}
	}
}
