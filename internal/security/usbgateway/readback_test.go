package usbgateway

import "testing"

func TestReadbackAcceptsObservedBFEIndexedFlag(t *testing.T) {
	// Actual value from 0.8.12's Windows service.log on the user's host.
	for _, flags := range []uint32{0, 0x40} {
		if err := validateFilterFlags(flags); err != nil {
			t.Fatal(err)
		}
	}
	// Do not waive disabled, persistent, context, action-right or unknown flags.
	for bit := uint(0); bit < 32; bit++ {
		flags := uint32(1) << bit
		if flags == 0x40 {
			continue
		}
		for _, value := range []uint32{flags, flags | 0x40} {
			if validateFilterFlags(value) == nil {
				t.Fatalf("accepted enforcement flag 0x%x", value)
			}
		}
	}
}

func TestReadbackConditionsMatchFieldsAcrossReordering(t *testing.T) {
	want := []string{localInterface, "{d78e1e87-8644-4ea5-9437-d809ecefc971}"}
	order, err := conditionOrder(want, []string{want[1], want[0]})
	if err != nil || len(order) != 2 || order[0] != 1 || order[1] != 0 {
		t.Fatal(order, err)
	}
	for _, got := range [][]string{nil, {want[0]}, {want[0], want[0]}, {want[1], forwardInterface}, {want[0], want[1], forwardInterface}} {
		if _, err := conditionOrder(want, got); err == nil {
			t.Fatalf("accepted missing/duplicate/widened fields: %v", got)
		}
	}
}
