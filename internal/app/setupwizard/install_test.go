package setupwizard

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestLegacyCleanupFollowsComponentPreparation(t *testing.T) {
	for _, cleanup := range []bool{true, false} {
		var calls []string
		a := InstallationActions{
			Check:   func() (bool, error) { calls = append(calls, "check"); return cleanup, nil },
			Prepare: func(_ context.Context, id string) error { calls = append(calls, id); return nil },
			Cleanup: func(context.Context) error { calls = append(calls, "cleanup"); return nil },
			Install: func(context.Context) (string, error) { calls = append(calls, "install"); return "App", nil },
		}
		path, e := Install(context.Background(), Options{IPad: true, MacTools: true}, a)
		want := []string{"check", "wintun", "dotnet", "apple-support", "apple-driver", "zadig"}
		if cleanup {
			want = append(want, "cleanup")
		}
		want = append(want, "install")
		if e != nil || path != "App" || !reflect.DeepEqual(calls, want) {
			t.Fatalf("path=%s, err=%v, calls=%v", path, e, calls)
		}
	}
}

func TestFailedOrCancelledPreparationPreservesResiduals(t *testing.T) {
	for _, phase := range []string{"check", "prepare", "cancel", "cleanup"} {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		failure := errors.New("blocked")
		prepared, removed, installed := 0, 0, 0
		a := InstallationActions{
			Check: func() (bool, error) {
				if phase == "check" {
					return false, failure
				}
				return true, nil
			},
			Prepare: func(_ context.Context, id string) error {
				prepared++
				if phase == "prepare" && id == "dotnet" {
					return failure
				}
				if phase == "cancel" && id == "dotnet" {
					cancel()
				}
				return nil
			},
			Cleanup: func(context.Context) error {
				removed++
				if phase == "cleanup" {
					return failure
				}
				return nil
			},
			Install: func(context.Context) (string, error) { installed++; return "App", nil },
		}
		_, e := Install(ctx, Options{}, a)
		if e == nil || installed != 0 {
			t.Fatalf("%s continued installation", phase)
		}
		if phase == "check" && prepared != 0 {
			t.Fatal("failed inspection prepared components")
		}
		if phase != "cleanup" && removed != 0 {
			t.Fatal("failed/cancelled preparation removed residuals")
		}
	}
}

func TestPayloadPreflightFailureRecordsCauseBeforeAnyMutation(t *testing.T) {
	var events []string
	mutations := 0
	_, err := Install(context.Background(), Options{}, InstallationActions{
		Check:   func() (bool, error) { return true, errors.New("INSTALL_PUBLISHER_DESKTOP_INDEX_REQUIRED") },
		Prepare: func(context.Context, string) error { mutations++; return nil },
		Cleanup: func(context.Context) error { mutations++; return nil },
		Install: func(context.Context) (string, error) { mutations++; return "", nil },
		Record: func(stage, state string, err error) {
			events = append(events, stage+":"+state)
			if state == "failed" && err == nil {
				t.Fatal("failure cause omitted")
			}
		},
	})
	if err == nil || mutations != 0 || !reflect.DeepEqual(events, []string{"preflight:started", "preflight:failed"}) {
		t.Fatal(err, mutations, events)
	}
}
