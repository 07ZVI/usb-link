package netconfig

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type permissionPlanStub struct {
	fragment string
	finish   func() error
}

func (p permissionPlanStub) Fragment() string             { return p.fragment }
func (p permissionPlanStub) Finish(context.Context) error { return p.finish() }

func TestResidentVerifiedReuseDoesNotLaunchPowerShell(t *testing.T) {
	reads := 0
	p := permissionPlanStub{finish: func() error { reads++; return nil }}
	err := CompleteResidentPermissionBatch(context.Background(), "", []ResidentPermissionPlan{p, p}, func(context.Context, string) error { t.Fatal("reuse started PowerShell"); return nil })
	if err != nil || reads != 2 {
		t.Fatal("reused scopes were not freshly verified", err, reads)
	}
}
func TestPartialBatchFailureCannotAdmitConnection(t *testing.T) {
	processFailure := errors.New("provider failed halfway")
	readFailure := errors.New("second rule incomplete")
	reads, runs := 0, 0
	first := permissionPlanStub{"repair-first", func() error { reads++; return nil }}
	second := permissionPlanStub{"repair-second", func() error { reads++; return readFailure }}
	err := CompleteResidentPermissionBatch(context.Background(), "owned-network", []ResidentPermissionPlan{first, second}, func(_ context.Context, script string) error {
		runs++
		if !strings.Contains(script, "owned-network\nrepair-first\nrepair-second") {
			t.Fatal("ordered scopes lost")
		}
		return processFailure
	})
	if runs != 1 || reads != 2 || !errors.Is(err, processFailure) || !errors.Is(err, readFailure) {
		t.Fatal("partial success admitted or remaining obligations not audited", err)
	}
}
func TestCancelledBatchNeverLaunchesOrCommits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := permissionPlanStub{"repair", func() error { t.Fatal("cancelled plan committed"); return nil }}
	err := CompleteResidentPermissionBatch(ctx, "network", []ResidentPermissionPlan{p}, func(context.Context, string) error { t.Fatal("cancelled script started"); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
