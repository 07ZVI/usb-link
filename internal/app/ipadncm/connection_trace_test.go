package ipadncm

import (
	"encoding/json"
	"suhang/usbnet/internal/buildinfo"
	"testing"
	"time"
)

func TestConnectionStageCarriesObservationTimeForNativeCorrelation(t *testing.T) {
	m := newMonitorDiagnosticCounter()
	m.deviceKind, m.attempt = "iPad", 7
	m.attemptStarted = time.Now()
	before := time.Now()
	m.stage("usb_set_mode_request_begin", "own_operation_started", false)
	after := time.Now()
	r := m.snapshot()
	if len(r.ConnectionTrace) != 1 {
		t.Fatal(r)
	}
	e := r.ConnectionTrace[0]
	at, err := time.Parse(time.RFC3339Nano, e.UTC)
	if err != nil || at.Before(before) || at.After(after) || e.Attempt != 7 || e.ElapsedMS < 0 {
		t.Fatal("operation time cannot be aligned to native metadata", e, err)
	}
	b, err := json.Marshal(e)
	var decoded ConnectionEvent
	if err != nil || json.Unmarshal(b, &decoded) != nil || decoded.UTC != e.UTC || decoded.ElapsedMS != e.ElapsedMS {
		t.Fatal("observation time lost in snapshot", string(b), err)
	}
}

func TestPreSwitchControlOperationsReachTrustTimeline(t *testing.T) {
	oldMonitor, oldTrust, oldFlag := monitorDiagnostics, trustDiagnostics, buildinfo.LocalDiagnostics
	t.Cleanup(func() {
		monitorDiagnostics, trustDiagnostics, buildinfo.LocalDiagnostics = oldMonitor, oldTrust, oldFlag
	})
	monitorDiagnostics = newMonitorDiagnosticCounter()
	trustDiagnostics = &trustDiagnosticState{}
	trustDiagnostics.start(time.Now(), "control-window-test")
	buildinfo.LocalDiagnostics = "true"
	RecordConnectionAttemptFor("iPad")
	for _, operation := range []string{"usb_control_open", "usb_get_mode", "usb_mode_switch", "usb_set_mode_request"} {
		RecordConnectionOperation(operation)()
	}
	events := TrustDiagnosticsSnapshot().Events
	if len(events) != 9 {
		t.Fatalf("control operation windows missing: %+v", events)
	}
	for i, stage := range []string{"usb_control_open_begin", "usb_control_open_end", "usb_get_mode_begin", "usb_get_mode_end", "usb_mode_switch_begin", "usb_mode_switch_end", "usb_set_mode_request_begin", "usb_set_mode_request_end"} {
		if events[i+1].Kind != stage || events[i+1].Attempt != 1 {
			t.Fatalf("control operation attribution mismatch: %+v", events[i+1])
		}
	}
}

func TestModeSwitchTraceRetainsReactivationAndRejectsLateCompletion(t *testing.T) {
	previous := monitorDiagnostics
	monitorDiagnostics = newMonitorDiagnosticCounter()
	t.Cleanup(func() { monitorDiagnostics = previous })
	RecordConnectionAttemptFor("iPad")
	for i := 0; i < 2; i++ {
		done := RecordConnectionOperation("usb_mode_switch")
		monitorDiagnostics.notice(0x8000)
		done()
	}
	r := ConnectionMonitorDiagnostics()
	if len(r.ConnectionTrace) != 4 || len(r.NoticeSamples) != 2 {
		t.Fatal("mode reactivation was omitted", r)
	}
	for i, event := range r.ConnectionTrace {
		stage := "usb_mode_switch_begin"
		if i%2 == 1 {
			stage = "usb_mode_switch_end"
		}
		if event.Attempt != 1 || event.Stage != stage {
			t.Fatal("switch boundaries were not retained", event)
		}
	}
	for _, notice := range r.NoticeSamples {
		if notice.Operation != "usb_mode_switch" {
			t.Fatal("mode window missing from notification correlation", notice)
		}
	}
	done := RecordConnectionOperation("usb_mode_switch")
	RecordConnectionAttemptFor("iPad")
	done()
	if len(ConnectionMonitorDiagnostics().ConnectionTrace) != 5 {
		t.Fatal("late completion was attributed to the next attempt")
	}
}

func TestConnectionTraceIsAttemptScopedBoundedAndIndependent(t *testing.T) {
	m := newMonitorDiagnosticCounter()
	m.deviceKind = "iPad"
	m.attempt = 1
	m.attemptStarted = time.Now()
	m.stage("dhcp_ack_sent", "reply", true)
	m.stage("dhcp_ack_sent", "duplicate", true)
	if len(m.snapshot().ConnectionTrace) != 1 {
		t.Fatal("repeated ACK shifted first completion time")
	}
	if m.snapshot().ConnectionTrace[0].Stage == "ip_configured" {
		t.Fatal("ACK is not applied address evidence")
	}
	for i := 0; i < 150; i++ {
		m.stage("device_restart_begin", "window", false)
	}
	r := m.snapshot()
	if len(r.ConnectionTrace) != 128 || r.DroppedConnectionEvents != 23 {
		t.Fatal(r)
	}
	r.ConnectionTrace[0].Stage = "changed"
	if m.snapshot().ConnectionTrace[0].Stage == "changed" {
		t.Fatal("snapshot aliases trace")
	}
	m.deviceKind = "Mac"
	m.stage("usb_enumerated", "other peer", true)
	if m.snapshot().ConnectionTrace[len(r.ConnectionTrace)-1].Stage == "usb_enumerated" {
		t.Fatal("Mac evidence entered iPad attempt")
	}
	m.deviceKind = "iPad"
	m.operation = "device_restart"
	m.operationAt = time.Now()
	m.notice(7)
	if m.snapshot().NoticeSamples[0].Operation != "device_restart" {
		t.Fatal("missing correlation")
	}
	m.operationAt = time.Now().Add(-3 * time.Second)
	m.notice(7)
	if m.snapshot().NoticeSamples[1].Operation != "" {
		t.Fatal("stale operation attributed")
	}
	m.attempt = 2
	m.stageFor(1, "device_restart_end", "previous attempt completed late", false)
	if m.snapshot().ConnectionTrace[len(r.ConnectionTrace)-1].Stage == "device_restart_end" {
		t.Fatal("old operation was credited to new attempt")
	}
}
