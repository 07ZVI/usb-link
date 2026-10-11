package connectioninstall

import "context"

// Callers have already proved the exact legacy objects under the core lease.
// Backup must be durable and independently read back before rechecking or
// deleting anything. Once deletion begins, finish the bounded cleanup before
// observing cancellation; partial failures retain the backup for safe retry.
type deletedInstallRemoval struct {
	Backup       func() (string, error)
	Recheck      func() error
	Service      func() error
	Registration func() error
	VerifyClean  func() error
}

func runDeletedInstallRemoval(ctx context.Context, a deletedInstallRemoval) (string, error) {
	if e := ctx.Err(); e != nil {
		return "", e
	}
	backup, e := a.Backup()
	if e != nil {
		return backup, e
	}
	if e := a.Recheck(); e != nil {
		return backup, e
	}
	if e := ctx.Err(); e != nil {
		return backup, e
	}
	if e := a.Service(); e != nil {
		return backup, e
	}
	if e := a.Registration(); e != nil {
		return backup, e
	}
	return backup, a.VerifyClean()
}
