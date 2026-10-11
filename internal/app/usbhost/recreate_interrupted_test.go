package usbhost

import (
	"bytes"
	"errors"
	"testing"
)

func TestInterruptedRecreateDoesNotTouchOtherObligations(t *testing.T) {
	_, _, attempt := recreateFixture()
	closing := attempt
	closing.State = "closing"
	for _, tc := range []struct {
		t     recreateTransaction
		found bool
	}{
		{attempt, false},
		{closing, true},
		{readyRecreate(attempt), true},
		{recreateTransaction{}, false},
	} {
		attempted, err := settleInterruptedRecreate(tc.t, tc.found,
			func() ([]byte, error) { t.Fatal("unselected journal/conflicts read"); return nil, nil },
			func(recreateTransaction, []byte) error { t.Fatal("unselected settlement invoked"); return nil })
		if attempted || err != nil {
			t.Fatalf("unselected phase %q changed: %v %v", tc.t.State, attempted, err)
		}
	}
}

func TestInterruptedRecreatePreservesSelectedReceiptAndOriginalErrors(t *testing.T) {
	_, old, attempt := recreateFixture()
	for _, selected := range []recreateTransaction{attempt, mappedRecreate(attempt)} {
		for _, prepareFails := range []bool{false, true} {
			failure := errors.New("retained original failure")
			prepared, finished := 0, 0
			attempted, err := settleInterruptedRecreate(selected, true, func() ([]byte, error) {
				prepared++
				if prepareFails {
					return nil, failure
				}
				return old, nil
			}, func(got recreateTransaction, journal []byte) error {
				finished++
				if got != selected || !bytes.Equal(journal, old) {
					t.Fatal("early path changed protected receipt/journal")
				}
				return failure
			})
			if !attempted || err != failure || prepared != 1 || (prepareFails && finished != 0) || (!prepareFails && finished != 1) {
				t.Fatalf("%s failure propagation changed: attempted=%v err=%v calls=%d/%d", selected.State, attempted, err, prepared, finished)
			}
		}
	}
}

func TestInterruptedRecreateCannotTurnElapsedTimeIntoRebootProof(t *testing.T) {
	_, old, attempt := recreateFixture()
	for _, selected := range []recreateTransaction{attempt, mappedRecreate(attempt)} {
		for _, ticks := range []uint64{0, selected.Ticks, selected.Ticks + 1, selected.Ticks - 1} {
			absenceReads := 0
			attempted, err := settleInterruptedRecreate(selected, true, func() ([]byte, error) { return old, nil }, func(got recreateTransaction, b []byte) error {
				if position, err := recreateJournalPosition(got, b); err != nil || position != "old" {
					t.Fatalf("old protected journal lost: %s %v", position, err)
				}
				if err := recreateUnknownRecoveryGate(got, ticks); err != nil {
					return err
				}
				return verifyRecreateAbsentAddressReads(got, func(uint64) (int, error) { absenceReads++; return 0, nil })
			})
			reset := ticks > 0 && ticks < selected.Ticks
			if !attempted || (err == nil) != reset || (!reset && absenceReads != 0) || (reset && absenceReads != len(recreateAbsenceLUIDs(selected))) {
				t.Fatalf("counter %d phase %s changed fence: %v reads=%d", ticks, selected.State, err, absenceReads)
			}
		}
	}
}
