//go:build darwin

package macagent

import (
	"errors"
	"fmt"
	"os"
)

func stageOwned(prefix string, b []byte) (string, error) {
	f, e := os.CreateTemp(root, prefix)
	if e != nil {
		return "", e
	}
	p := f.Name()
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		os.Remove(p)
		return "", errors.Join(e, ce)
	}
	if e = os.Chmod(p, 0700); e != nil {
		os.Remove(p)
		return "", e
	}
	return p, nil
}

// Stage everything before stopping the verified old job. Change only our
// protected binary/state, retaining a recoverable backup on failed rollback.
func upgrade() (err error) {
	if _, e := os.Lstat(root); os.IsNotExist(e) {
		return install("")
	}
	old, e := load()
	if e != nil {
		return e
	}
	if secure(plistPath, true) != nil {
		return fmt.Errorf("unowned launchd job")
	}
	p, e := os.ReadFile(plistPath)
	if e != nil || string(p) != plist {
		return fmt.Errorf("changed launchd job")
	}
	self, e := os.Executable()
	if e != nil || self == binary {
		return fmt.Errorf("run the new helper to upgrade")
	}
	b, e := os.ReadFile(self)
	if e != nil || len(b) < 1024 || len(b) > 16*1024*1024 {
		return fmt.Errorf("invalid new helper")
	}
	if hash(b) == old.BinarySHA {
		return nil
	}
	prior, e := os.ReadFile(binary)
	if e != nil || hash(prior) != old.BinarySHA {
		return fmt.Errorf("old helper changed")
	}
	backup, e := stageOwned("upgrade-previous-*", prior)
	if e != nil {
		return e
	}
	preserveBackup := false
	defer func() {
		if !preserveBackup {
			os.Remove(backup)
		}
	}()
	stage, e := stageOwned("upgrade-next-*", b)
	if e != nil {
		return e
	}
	defer os.Remove(stage)
	if _, e = run("/bin/launchctl", "bootout", "system/"+label); e != nil {
		if _, x := run("/bin/launchctl", "print", "system/"+label); x == nil {
			return e
		}
	}
	locked, e := lock()
	if e != nil {
		run("/bin/launchctl", "bootstrap", "system", plistPath)
		return e
	}
	released := false
	release := func() {
		if !released {
			locked.Close()
			released = true
		}
	}
	defer release()
	current, e := load()
	if e != nil || current.BinarySHA != old.BinarySHA {
		return fmt.Errorf("helper changed during upgrade")
	}
	old = current
	changed, completed := false, false
	defer func() {
		if completed {
			return
		}
		if changed {
			// If bootstrap partly succeeded, stop our same validated job first.
			if _, x := run("/bin/launchctl", "print", "system/"+label); x == nil {
				if _, x = run("/bin/launchctl", "bootout", "system/"+label); x != nil {
					preserveBackup = true
					err = errors.Join(err, x)
					return
				}
			}
			if x := os.Rename(backup, binary); x != nil {
				preserveBackup = true
				err = errors.Join(err, x)
				return
			}
			if x := save(old); x != nil {
				err = errors.Join(err, x)
				return
			}
		}
		release()
		_, x := run("/bin/launchctl", "bootstrap", "system", plistPath)
		err = errors.Join(err, x)
	}()
	if e = os.Rename(stage, binary); e != nil {
		return e
	}
	changed = true
	current.BinarySHA = hash(b)
	if e = save(current); e != nil {
		return e
	}
	if _, e = load(); e != nil {
		return e
	}
	release()
	if _, e = run("/bin/launchctl", "bootstrap", "system", plistPath); e != nil {
		return e
	}
	completed = true
	return nil
}
