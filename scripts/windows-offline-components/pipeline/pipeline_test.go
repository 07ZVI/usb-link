package pipeline

import (
	"context"
	"errors"
	"testing"
)

func TestCompleteBundlePreflightBeforeAnyMachineChange(t *testing.T) {
	for _, bad := range []int{0, 1, 2} {
		changed := 0
		r := Run(context.Background(), []Component{{ID: "a"}, {ID: "b"}, {ID: "c"}}, Actions{
			Verify: func(_ context.Context, c Component) error {
				if c.ID == []string{"a", "b", "c"}[bad] {
					return errors.New("corrupted package")
				}
				return nil
			},
			Detect:  func(context.Context, Component) (bool, error) { changed++; return false, nil },
			Prepare: func(context.Context, Component) error { changed++; return nil },
		}, false)
		if changed != 0 || r.Outcome != "failed" || r.Components[bad].State != "failed" {
			t.Fatalf("bad=%d machine changes=%d report=%+v", bad, changed, r)
		}
	}
}

func TestRerunReusesCompletedComponentsAndReportsRestart(t *testing.T) {
	prepared := []string{}
	r := Run(context.Background(), []Component{{ID: "dotnet"}, {ID: "apple-support"}}, Actions{
		Verify: func(context.Context, Component) error { return nil },
		Detect: func(_ context.Context, c Component) (bool, error) { return c.ID == "dotnet", nil },
		Prepare: func(_ context.Context, c Component) error {
			prepared = append(prepared, c.ID)
			return ErrRebootRequired
		},
	}, false)
	if len(prepared) != 1 || prepared[0] != "apple-support" || r.Components[0].State != "reused" || !r.RebootRequired || r.Outcome != "reboot-required" {
		t.Fatalf("prepared=%v report=%+v", prepared, r)
	}
}

func TestFailureOrCancellationRetainsEarlierCompletion(t *testing.T) {
	for _, cancelRun := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		prepared := []string{}
		r := Run(ctx, []Component{{ID: "a"}, {ID: "b"}, {ID: "c"}}, Actions{
			Verify: func(context.Context, Component) error { return nil },
			Detect: func(context.Context, Component) (bool, error) { return false, nil },
			Prepare: func(_ context.Context, c Component) error {
				prepared = append(prepared, c.ID)
				if c.ID == "b" {
					if cancelRun {
						cancel()
						return ctx.Err()
					}
					return errors.New("installation failed")
				}
				return nil
			},
		}, false)
		cancel()
		if len(prepared) != 2 || r.Components[0].State != "ready" || r.Components[1].State != "failed" || r.Components[2].State != "not-run" || r.Outcome != "failed" {
			t.Fatalf("prepared=%v report=%+v", prepared, r)
		}
	}
}
