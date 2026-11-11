package connectioninstall

import (
	"errors"
	"fmt"
)

// Retire each share independently. Persist its removal before restoring the
// separate ACL journal, so an unavailable/changed folder cannot resurrect a
// deleted share or prevent the other shares from being turned off.
func retireSMBItems[T any](items []T, remove func(T) error, persist func([]T) error, restore func(T) error) error {
	remaining := append([]T(nil), items...)
	var failures []error
	removed := 0
	for i, item := range items {
		if err := remove(item); err != nil {
			failures = append(failures, err)
			continue
		}
		pos := i - removed
		next := append([]T(nil), remaining[:pos]...)
		next = append(next, remaining[pos+1:]...)
		if err := persist(next); err != nil {
			failures = append(failures, err)
			continue
		}
		remaining = next
		removed++
		if err := restore(item); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// A failed identity change must restore the previous sharing state too. Do
// not republish shares if rollback itself was not confirmed.
func changeSMBIdentity(active bool, change, rollback, resume func() error) error {
	err := change()
	if err != nil && rollback != nil {
		if recovery := rollback(); recovery != nil {
			return errors.Join(err, recovery)
		}
	}
	if active {
		err = errors.Join(err, resume())
	}
	return err
}

// Save the encrypted intent before asking Windows to change a password. If
// the process exits between calls, startup retains the pending journal and
// publishing the account requires an explicit password recovery operation.
func commitSMBPassword(stage, change, commit, rollback func() error) error {
	if err := stage(); err != nil {
		return err
	}
	if err := change(); err != nil {
		return errors.Join(err, rollback())
	}
	if err := commit(); err != nil {
		return errors.Join(err, rollback())
	}
	return nil
}

func sameSMBGrants(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := map[string]int{}
	for _, sid := range a {
		counts[sid]++
	}
	for _, sid := range b {
		if counts[sid] == 0 {
			return false
		}
		counts[sid]--
	}
	return true
}

// Grant the filesystem before opening the network entry; revoke the network
// entry before cleanup that may fail for an offline drive. Commit only after
// both steps succeed so a failed cleanup remains explicitly retryable.
func changeSMBGuestPermissions(disabling bool, filesystem, network, commit func() error) error {
	first, second := filesystem, network
	if disabling {
		first, second = network, filesystem
	}
	if e := first(); e != nil {
		return e
	}
	if e := second(); e != nil {
		return e
	}
	return commit()
}

// An interrupted change always needs reconciliation of both permission layers,
// even if its network ACL already equals a subsequent, reversed local request.
// The caller has verified the current descriptor against the protected journal.
func planSMBGuestChange(previous, pendingTarget, desired string, pending, atPendingTarget bool) (current string, update bool) {
	current = previous
	if pending && atPendingTarget {
		current = pendingTarget
	}
	return current, pending || current != desired
}

// A handoff never changes the Windows share itself. Revoke selected membership
// before relinquishing recovery records, leaving an orphan receipt retryable
// if cleanup fails, rather than allowing startup to republish the directory.
func handoffSMBItem(revoke, retainPermissions, relinquish func() error) error {
	if e := revoke(); e != nil {
		return e
	}
	if e := retainPermissions(); e != nil {
		return e
	}
	return relinquish()
}

func disableSMBGuest(revokeShares, restoreIdentity func() error) error {
	shareError := revokeShares()
	return errors.Join(shareError, restoreIdentity())
}

// Revoke publication intent first. An interrupted retire retains its ownership
// receipt for retry, while an interrupted ACL cleanup retains only recovery
// evidence. Neither failure is allowed to select the folder again.
func cancelSelectedSMBFolder(revoke, retire, restore func() error) error {
	if err := revoke(); err != nil {
		return err
	}
	if err := retire(); err != nil {
		return fmt.Errorf("已取消自動共享；Windows 共享移除待完成，請重試：%w", err)
	}
	if err := restore(); err != nil {
		return fmt.Errorf("共享已取消；資料夾權限恢復待完成，請重試或保留目前權限：%w", err)
	}
	return nil
}

func forgetNativeSMBFolder(c *nativeSMBConfiguration, id string) {
	shares := c.Shares[:0]
	for _, s := range c.Shares {
		if s.ID != id {
			shares = append(shares, s)
		}
	}
	c.Shares = shares
	forgetSMBShareName(c, id)
	access := c.Access[:0]
	for _, a := range c.Access {
		if a.ID != id {
			access = append(access, a)
		}
	}
	c.Access = access
}
