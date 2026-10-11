package netconfig

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWintunCloseSettleRequiresTwoCompletedObservations(t *testing.T) {
	for name, reads := range map[string][]bool{"complete": {true, true}, "stillPresent": {false, true, true}, "racedNewMapping": {true, false, true, true}} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			poll := make(chan time.Time, 1)
			poll <- time.Time{}
			err := waitWintunCloseSettle(context.Background(), func() (bool, error) {
				if calls >= len(reads) {
					t.Fatal("unexpected extra read")
				}
				v := reads[calls]
				calls++
				return v, nil
			}, nil, poll)
			if err != nil || calls != len(reads) {
				t.Fatalf("unproved completion: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestWintunCloseSettleDoesNotTurnUnknownTimeoutOrCancellationIntoAbsence(t *testing.T) {
	unknown := errors.New("native enumeration unavailable")
	for _, at := range []int{1, 2} {
		calls := 0
		err := waitWintunCloseSettle(context.Background(), func() (bool, error) {
			calls++
			if calls == at {
				return false, unknown
			}
			return true, nil
		}, nil, nil)
		if !errors.Is(err, unknown) || calls != at {
			t.Fatalf("unknown read admitted: at=%d calls=%d err=%v", at, calls, err)
		}
	}
	deadline := make(chan time.Time, 1)
	deadline <- time.Time{}
	err := waitWintunCloseSettle(context.Background(), func() (bool, error) { return false, nil }, deadline, nil)
	if err == nil || err.Error() != "USB_MAC_LIFETIME_CLOSE_ABSENCE_UNCONFIRMED" {
		t.Fatal("elapsed time claimed absence")
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err = waitWintunCloseSettle(ctx, func() (bool, error) { calls++; cancel(); return true, nil }, nil, nil)
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("cancellation between reads was admitted")
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	err = waitWintunCloseSettle(ctx, func() (bool, error) { t.Fatal("cancelled owner was queried"); return false, nil }, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled owner admitted")
	}
}
