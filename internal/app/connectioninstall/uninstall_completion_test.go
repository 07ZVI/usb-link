package connectioninstall

import (
	"errors"
	"reflect"
	"testing"
)

func TestUninstallCompletionRefusesUnknownObligationsAndChangedOwner(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		initial, restore, final bool
		want                    []string
	}{
		{"undrained_core", false, true, true, []string{"verify"}},
		{"ghost_or_missing_original", true, false, true, []string{"verify", "restore"}},
		{"binding_changed_after_restore", true, true, false, []string{"verify", "restore", "verify"}},
		{"fully_proven", true, true, true, []string{"verify", "restore", "verify", "remove"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			count := 0
			refused := errors.New("refused")
			err := finishVerifiedUninstall(func() error {
				calls = append(calls, "verify")
				count++
				if count == 1 && !tc.initial || count == 2 && !tc.final {
					return refused
				}
				return nil
			}, func() error {
				calls = append(calls, "restore")
				if !tc.restore {
					return refused
				}
				return nil
			}, func() error { calls = append(calls, "remove"); return nil })
			if !reflect.DeepEqual(calls, tc.want) || (err == nil) != (tc.initial && tc.restore && tc.final) {
				t.Fatalf("calls=%v err=%v", calls, err)
			}
		})
	}
}

func TestUninstallCompletionRequiresEveryProofAndPreservesRemovalFailure(t *testing.T) {
	ok := func() error { return nil }
	failed := errors.New("exact removal incomplete")
	for _, funcs := range [][3]func() error{{nil, ok, ok}, {ok, nil, ok}, {ok, ok, nil}} {
		if finishVerifiedUninstall(funcs[0], funcs[1], funcs[2]) == nil {
			t.Fatal("missing proof accepted")
		}
	}
	if !errors.Is(finishVerifiedUninstall(ok, ok, func() error { return failed }), failed) {
		t.Fatal("removal failure lost")
	}
}
