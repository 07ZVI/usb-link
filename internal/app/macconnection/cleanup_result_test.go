package macconnection

import (
	"errors"
	"reflect"
	"testing"
)

func TestMacCleanupRequiresBothIndependentRestorations(t *testing.T) {
	failure := errors.New("native recovery failed")
	for _, tc := range []struct {
		name          string
		recovery, mtu error
		confirmed     bool
	}{
		{"both verified", nil, nil, true},
		{"session failed", failure, nil, false},
		{"MTU failed after session success", nil, failure, false},
		{"both failed", failure, failure, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var order []string
			r := runMacCleanup(func() error { order = append(order, "session"); return tc.recovery }, func() error { order = append(order, "MTU"); return tc.mtu })
			if !reflect.DeepEqual(order, []string{"session", "MTU"}) || r.confirmed() != tc.confirmed || r.RecoveryError != tc.recovery || r.MTUError != tc.mtu {
				t.Fatalf("independent cleanup obligation lost: %+v, %v", r, order)
			}
		})
	}
}
