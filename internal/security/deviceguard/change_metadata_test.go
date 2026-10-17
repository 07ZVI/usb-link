package deviceguard

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestChangeMetadataPreservesCallbackTimeAndUsesPrivateRunKeys(t *testing.T) {
	a, err := newChangeMetadataStream()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newChangeMetadataStream()
	if err != nil {
		t.Fatal(err)
	}
	const root = `USB\VID_05AC&PID_12AB\PRIVATE_SERIAL_NEVER_EXPORT`
	const child = `USB\VID_05AC&PID_12AB&MI_01\PRIVATE_SERIAL_NEVER_EXPORT`
	at := time.Date(2026, 10, 17, 2, 3, 4, 123456789, time.UTC)
	a.offer(0, root, at)
	a.offer(7, strings.ToLower(root), at.Add(time.Millisecond))
	a.offer(8, child, at.Add(2*time.Millisecond))
	b.offer(0, root, at)
	first, same, iface, other := <-a.Events(), <-a.Events(), <-a.Events(), <-b.Events()
	if first.UTC != at.Format(time.RFC3339Nano) || first.Sequence != 1 || same.Sequence != 2 || iface.Sequence != 3 || first.Action != "usb_interface_arrival" || iface.Action != "instance_started" {
		t.Fatal(first, same, iface)
	}
	if first.NodeKey != same.NodeKey || first.NodeKey == iface.NodeKey || first.NodeKey == other.NodeKey || first.Interface != -1 || iface.Interface != 1 || first.Product != 0x12ab {
		t.Fatal("wrong per-subscription node association", first, same, iface, other)
	}
	encoded, err := json.Marshal([]ChangeMetadata{first, same, iface, other})
	if err != nil || strings.Contains(string(encoded), "PRIVATE") || strings.Contains(string(encoded), "USB\\") {
		t.Fatal("instance identity leaked", string(encoded), err)
	}
}

func TestChangeMetadataOverflowSequenceAndStopAdmissionAreExplicit(t *testing.T) {
	s, err := newChangeMetadataStream()
	if err != nil {
		t.Fatal(err)
	}
	const root = `USB\VID_05AC&PID_12AB\PRIVATE`
	for i := 0; i < changeMetadataCapacity+3; i++ {
		s.offer(7, root, time.Now())
	}
	if got := s.Stats(); got.Observed != 131 || got.QueueDropped != 3 {
		t.Fatal(got)
	}
	for i := uint64(1); i <= changeMetadataCapacity; i++ {
		if event := <-s.Events(); event.Sequence != i {
			t.Fatal(event)
		}
	}
	s.offer(9, root, time.Now())
	if e := <-s.Events(); e.Sequence != 132 {
		t.Fatal("overflow was hidden in callback sequence", e)
	}
	s.StopAdmission()
	before := s.Stats()
	s.offer(8, root, time.Now())
	if after := s.Stats(); before != after || len(s.events) != 0 || s.salt != ([32]byte{}) {
		t.Fatal("closed stream captured metadata or retained its salt", after)
	}
}

func TestChangeMetadataRejectsUnknownActionsAndForeignDevices(t *testing.T) {
	s, err := newChangeMetadataStream()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		action uintptr
		node   string
	}{
		{6, `USB\VID_05AC&PID_12AB\PRIVATE`},
		{7, `USB\VID_1234&PID_12AB\PRIVATE`},
		{7, `USB\VID_05AC&PID_12ZZ\PRIVATE`},
		{7, `USB\VID_05AC&PID_12AB&MI_ZZ\PRIVATE`},
		{7, `USB\VID_05AC&PID_12AB`},
		{7, `USB\VID_05AC&PID_12AB\`},
	} {
		s.offer(item.action, item.node, time.Now())
	}
	if stats := s.Stats(); stats.Rejected != 6 || stats.Observed != 0 || len(s.events) != 0 {
		t.Fatal(stats)
	}
}

func TestChangeMetadataParseRejectionsHaveBoundedReasonsAndStopWithMaster(t *testing.T) {
	s, err := newChangeMetadataStream()
	if err != nil {
		t.Fatal(err)
	}
	s.reject(0)
	s.reject(2)
	s.reject(3)
	before := s.Stats()
	if before.Rejected != 3 || before.RejectedInterface != 1 || before.RejectedInstance != 1 || before.RejectedSize != 1 {
		t.Fatal(before)
	}
	s.StopAdmission()
	s.reject(0)
	if s.Stats() != before {
		t.Fatal("closed stream continued parsing admission")
	}
}

func BenchmarkChangeMetadataCallback(b *testing.B) {
	s, err := newChangeMetadataStream()
	if err != nil {
		b.Fatal(err)
	}
	const root = `USB\VID_05AC&PID_12AB\PRIVATE`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.offer(7, root, time.Now())
		select {
		case <-s.events:
		default:
		}
	}
}
