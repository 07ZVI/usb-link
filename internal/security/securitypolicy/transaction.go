package securitypolicy

import (
	"context"
	"fmt"
)

// HostBackend is a privileged OS boundary, separate from policy/UI/transports.
// Implementations must serialize changes and use compare-and-swap ownership:
// never overwrite GPO/MDM/third-party changes or use wildcard resource removal.
type HostBackend interface {
	Prepare(context.Context, HIDPlan) (Receipt, error)
	Apply(context.Context, Receipt) error
	Verify(context.Context, Receipt) (Evidence, error)
	Restore(context.Context, Receipt) error
}

type Receipt struct {
	ID      string
	Version int
}

type Journal interface {
	SavePending(Receipt) error // Durable, ACL-protected; before any OS mutation.
	Clear(Receipt) error       // Exact receipt only, after verified restoration.
}

// InstallHID leaves the recovery journal in place after success. Rollback uses
// its own context because cancelling the caller must not cancel restoration.
// Verification must establish OS enforcement, not merely registry read-back.
func InstallHID(ctx, recovery context.Context, b HostBackend, j Journal, p HIDPlan) (Evidence, error) {
	if b == nil || j == nil || ctx == nil || recovery == nil || recovery.Err() != nil || !p.Valid() {
		return Evidence{}, fmt.Errorf("SECURITY_EXECUTOR_UNAVAILABLE")
	}
	r, err := b.Prepare(ctx, p)
	if err != nil {
		return Evidence{}, err
	}
	if r.ID == "" || r.Version != 1 {
		return Evidence{}, fmt.Errorf("SECURITY_RECEIPT_INVALID")
	}
	if err = j.SavePending(r); err != nil {
		return Evidence{}, err
	}
	rollback := func(cause error) (Evidence, error) {
		if err := b.Restore(recovery, r); err != nil {
			return Evidence{State: Degraded, Code: "SECURITY_RECOVERY_REQUIRED", Scope: "host"}, fmt.Errorf("%w; restore: %v", cause, err)
		}
		if err := j.Clear(r); err != nil {
			return Evidence{State: Degraded, Code: "SECURITY_JOURNAL_RETAINED", Scope: "host"}, fmt.Errorf("%w; journal: %v", cause, err)
		}
		return Evidence{State: Degraded, Code: "SECURITY_CHANGE_RESTORED", Scope: "host"}, cause
	}
	if ctx.Err() != nil {
		return rollback(ctx.Err())
	}
	if err = b.Apply(ctx, r); err != nil {
		return rollback(err)
	}
	e, err := b.Verify(ctx, r)
	if err != nil {
		return rollback(err)
	}
	if ctx.Err() != nil || e.State != Verified || !e.EnforcementVerified || e.Scope != "host" {
		return rollback(fmt.Errorf("SECURITY_ENFORCEMENT_UNCONFIRMED"))
	}
	return e, nil
}
