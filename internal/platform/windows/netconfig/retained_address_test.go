package netconfig

import (
	"errors"
	"testing"
)

func TestRetainedMacAddressPhaseHasNoFactoryFallback(t *testing.T) {
	for _, x := range []struct {
		name             string
		retained, failed bool
		verify, create   int
	}{
		{"legacy", false, false, 0, 1}, {"legacy create fails", false, true, 0, 1}, {"owned retained", true, false, 1, 0}, {"changed retained", true, true, 1, 0}} {
		t.Run(x.name, func(t *testing.T) {
			nv, nc := 0, 0
			failure := errors.New("scope changed")
			e := runMacAddressPhase(x.retained, func() error {
				nv++
				if x.failed {
					return failure
				}
				return nil
			}, func() error {
				nc++
				if x.failed {
					return failure
				}
				return nil
			})
			if nv != x.verify || nc != x.create || (x.failed && e != failure) || (!x.failed && e != nil) {
				t.Fatal(nv, nc, e)
			}
		})
	}
}
