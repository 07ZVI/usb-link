//go:build windows && amd64

package connectioninstall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// CompleteInstalledUninstall retains the machine-wide lifecycle gate across
// restore-only work. It neither stops an unverified service nor grants a remote
// caller authority. The local installer has already obtained explicit consent
// and its share-zero recovery file. The verifier is valid only in this stack;
// callbacks must not re-enter lifecycle mutation APIs.
func CompleteInstalledUninstall(ctx context.Context, exe string, restore func(func() error) error) (reboot bool, result error) {
	result = withStoppedCoreForUninstall(ctx, exe, restore, func() error {
		var err error
		reboot, err = removeInstalledFiles(exe)
		return err
	})
	return
}

func withStoppedCoreForUninstall(ctx context.Context, exe string, restore func(func() error) error, removeFiles func() error) (result error) {
	if ctx == nil || restore == nil || removeFiles == nil || !windows.GetCurrentProcessToken().IsElevated() || VerifyCoreExecutable(exe) != nil {
		return fmt.Errorf("CORE_UNINSTALL_LOCAL_SOURCE_REQUIRED")
	}
	user, tokenError := windows.GetCurrentProcessToken().GetTokenUser()
	if tokenError != nil || !validPreparedUserSID(user.User.Sid.String()) {
		return errors.New("CORE_UNINSTALL_LOCAL_USER_REQUIRED")
	}
	localSID := user.User.Sid.String()
	if err := verifyUninstallUpgradeIdle(); err != nil {
		return err
	}
	unlock, err := coreLifecycleLock()
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unlock()) }()
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	expected, present, err := readCoreBinding()
	if err != nil {
		return err
	}
	if _, pending, err := readCoreTransition(); err != nil || pending {
		return fmt.Errorf("CORE_UNINSTALL_TRANSITION_PENDING")
	}
	if present && !strings.EqualFold(expected.Executable, exe) {
		return fmt.Errorf("CORE_UNINSTALL_SOURCE_CHANGED")
	}
	var active atomic.Bool
	active.Store(true)
	defer active.Store(false)
	verify := func() error {
		if !active.Load() {
			return errors.New("CORE_UNINSTALL_LEASE_EXPIRED")
		}
		if err := verifyUninstallUpgradeIdle(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if VerifyCoreExecutable(exe) != nil || !windows.GetCurrentProcessToken().IsElevated() {
			return fmt.Errorf("CORE_UNINSTALL_LOCAL_SOURCE_CHANGED")
		}
		b, has, err := readCoreBinding()
		if err != nil || has != present || has && b != expected {
			return fmt.Errorf("CORE_UNINSTALL_BINDING_CHANGED")
		}
		u, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil || u.User.Sid.String() != localSID || has && localSID != b.OwnerSID {
			return fmt.Errorf("CORE_UNINSTALL_OWNER_CHANGED")
		}
		s, binding, err := ownedCoreService(m)
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST && !has {
			return nil
		}
		if err != nil {
			return err
		}
		defer s.Close()
		if !has || binding != expected {
			return fmt.Errorf("CORE_UNINSTALL_SCM_BINDING_CHANGED")
		}
		state, err := s.Query()
		if err != nil || state.State != svc.Stopped {
			return fmt.Errorf("CORE_UNINSTALL_CORE_NOT_DRAINED")
		}
		return nil
	}
	return finishVerifiedUninstall(verify, func() error { return restore(verify) }, func() error {
		if present {
			if err := removeCoreServiceUnlocked(&expected); err != nil {
				return err
			}
		}
		// Still under the same machine-wide lease: no trusted installer can
		// replace the binding between removal and version/registration cleanup.
		if _, has, err := readCoreBinding(); err != nil || has {
			return fmt.Errorf("CORE_UNINSTALL_BINDING_REAPPEARED")
		}
		if _, pending, err := readCoreTransition(); err != nil || pending {
			return fmt.Errorf("CORE_UNINSTALL_TRANSITION_PENDING")
		}
		s, err := m.OpenService(CoreServiceName)
		if err == nil {
			s.Close()
			return fmt.Errorf("CORE_UNINSTALL_SERVICE_REAPPEARED")
		}
		if err != windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return fmt.Errorf("CORE_UNINSTALL_ABSENCE_UNPROVEN")
		}
		if err := verifyUninstallUpgradeIdle(); err != nil {
			return err
		}
		return removeFiles()
	})
}

// The fixed protected journal remains untouched. Reuse the same strict terminal
// selection as a prepared local install; an unknown result is never "no job".
func verifyUninstallUpgradeIdle() error {
	root, err := remoteRoot()
	if err != nil {
		return err
	}
	path := filepath.Join(root, "job.json")
	b, err := coreProtectedReadBounded(path, false, true, 32768)
	if err == windows.ERROR_FILE_NOT_FOUND || os.IsNotExist(err) {
		return nil
	}
	if err != nil || !preparedJournalUnique(b) {
		return errors.New("CORE_UNINSTALL_UPGRADE_JOURNAL_UNPROVEN")
	}
	var job UpdateJob
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&job) != nil || d.Decode(new(any)) != io.EOF || len(job.ID) != 32 || strings.Trim(job.ID, "0123456789abcdef") != "" {
		return errors.New("CORE_UNINSTALL_UPGRADE_JOURNAL_UNPROVEN")
	}
	if !preparedJobIdle(job.Status, job.CandidatePID, job.CandidateCreation, job.CandidateExecutable) {
		return errors.New("CORE_UNINSTALL_UPGRADE_NOT_IDLE")
	}
	return nil
}
