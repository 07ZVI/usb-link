package ipadncm

import (
	"testing"
	"time"
)

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
