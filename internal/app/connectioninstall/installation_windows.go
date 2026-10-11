//go:build windows && amd64

package connectioninstall

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"suhang/usbnet/internal/app/remoteupdate"
)

const installationReadyName = "installation-ready.json"

type installationReady struct {
	Product, SHA256 string
	PID             uint32
	Creation        uint64
}
type nativeInstallation struct{ app, candidate, previous, state string }

func installationPaths() (*nativeInstallation, error) {
	root, e := protectedRoot(true)
	if e != nil {
		return nil, e
	}
	updates, e := installationUpdatesDirectory()
	if e != nil {
		return nil, e
	}
	state, e := StateDirectory()
	if e != nil {
		return nil, e
	}
	return &nativeInstallation{filepath.Join(root, CurrentApplicationDirectory), filepath.Join(updates, "Candidate"), filepath.Join(updates, "Previous"), state}, nil
}

// The setup runs from its original download/USB location and exits after the
// transaction. No permanent copy of the setup is placed inside Program Files.
func InstallRelease(ctx context.Context, version string, archive io.ReaderAt, size int64) (path string, result error) {
	token := windows.GetCurrentProcessToken()
	u, e := token.GetTokenUser()
	session, se := shareTokenDWORD(token, windows.TokenSessionId)
	if e != nil || se != nil || !token.IsElevated() || session == 0 || !versionPattern.MatchString(version) {
		return "", fmt.Errorf("INSTALL_INTERACTIVE_ADMIN_REQUIRED")
	}
	release, e := acquireUpgradeJobMutex(`Global\USBLinkInstallation-v1`, 5000)
	if e != nil {
		return "", e
	}
	defer func() { result = errors.Join(result, release()) }()
	// Keep the SCM lease across publication and acceptance. Nested service calls
	// stay on this same OS thread; other launchers cannot start the backup image.
	unlock, e := coreLifecycleLock()
	if e != nil {
		return "", e
	}
	defer func() { result = errors.Join(result, unlock()) }()
	ops, e := installationPaths()
	if e != nil {
		return "", e
	}
	self, e := os.Executable()
	if e != nil {
		return "", e
	}
	sum, e := fileHash(self)
	if e != nil {
		return "", e
	}
	next := Receipt{ProductID, version, sum}
	t, present, e := readInstallationTransaction()
	if e != nil {
		return "", e
	}
	if present && t.Phase != InstallComplete && t.Phase != InstallRolledBack {
		if t.OwnerSID != u.User.Sid.String() || t.Next != next {
			return "", fmt.Errorf("INSTALL_PENDING_USE_ORIGINAL_SETUP")
		}
		if t.Phase == InstallStaged {
			if e = stageInstallationRelease(ops, t, self, archive, size); e != nil {
				return "", e
			}
		}
		completed, runError := ExecuteInstallation(ctx, t, ops)
		if runError != nil && completed.Phase == InstallStaged && ctx.Err() != nil {
			runError = errors.Join(runError, discardStagedInstallation(ops, t, self, archive, size))
		}
		return filepath.Join(ops.app, BinaryName), runError
	}
	if accepted, repair, err := inspectMissingAcceptedInstallation(version); err != nil {
		return "", err
	} else if repair {
		if err = repairMissingAcceptedInstallation(ops, accepted, self, archive, size); err != nil {
			return "", err
		}
		return filepath.Join(ops.app, BinaryName), nil
	}
	if e = PreflightLocalInstallation(); e != nil {
		return "", e
	}
	if e = recoverCoreServiceTransition(); e != nil {
		return "", e
	}
	previous, found, e := readCoreBinding()
	if e != nil {
		return "", e
	}
	if found {
		if previous.OwnerSID != u.User.Sid.String() {
			return "", fmt.Errorf("INSTALL_OWNER_CHANGED")
		}
		r, e := readReceipt(filepath.Dir(previous.Executable))
		if e != nil {
			return "", e
		}
		if r.Version == version && previous.SHA256 != sum {
			return "", fmt.Errorf("INSTALL_SAME_VERSION_CHANGED")
		}
		if remoteupdate.Newer(r.Version, version) {
			return "", fmt.Errorf("INSTALL_DOWNGRADE_USE_UNINSTALL_FIRST")
		}
		want, planError := plannedInstallationInventory(next, archive, size)
		if planError != nil {
			return "", planError
		}
		if previous.SHA256 == sum && strings.EqualFold(filepath.Dir(previous.Executable), ops.app) && verifyReleaseFiles(ops.app, want, false) == nil {
			return previous.Executable, VerifyCoreExecutable(previous.Executable)
		}
	}
	// Seal the planned inventory before materializing any candidate file. An
	// interrupted staging phase can resume using only this exact setup payload.
	inv, e := plannedInstallationInventory(next, archive, size)
	if e != nil {
		return "", e
	}
	t = InstallationTransaction{Schema: 1, Product: ProductID, OwnerSID: u.User.Sid.String(), Phase: InstallStaged, Next: next, NextFiles: inv}
	if found {
		m, err := mgr.Connect()
		if err != nil {
			return "", err
		}
		service, got, err := ownedCoreService(m)
		if err != nil {
			m.Disconnect()
			return "", err
		}
		config, err := service.Config()
		service.Close()
		m.Disconnect()
		if err != nil || got != previous {
			return "", fmt.Errorf("INSTALL_PREVIOUS_CONFIG_CHANGED")
		}
		t.PreviousStartType = config.StartType
		t.Previous = &previous
		t.PreviousFiles, e = releaseInventory(filepath.Dir(previous.Executable))
		if e != nil {
			return "", e
		}
	}
	startup := StartupTaskObservation{}
	// Candidate isn't materialized yet, so task discovery uses the independently
	// verified previous source. A first install has no startup task by default.
	if found {
		startup, e = ReadStartupTaskState(previous.Executable)
	} else {
		e = nil
	}
	if e != nil {
		return "", e
	}
	t.StartupEnabled = startup.Enabled
	if e = validateInstallationTransaction(t); e != nil {
		return "", e
	}
	if e = ops.Save(t); e != nil {
		return "", e
	}
	if e = stageInstallationRelease(ops, t, self, archive, size); e != nil {
		return "", e
	}
	completed, runError := ExecuteInstallation(ctx, t, ops)
	if runError != nil && completed.Phase == InstallStaged && ctx.Err() != nil {
		runError = errors.Join(runError, discardStagedInstallation(ops, t, self, archive, size))
	}
	return filepath.Join(ops.app, BinaryName), runError
}

var installationReleaseFiles = installationFiles{
	protect: func(path string, directory bool) error { _, e := coreProtectedRead(path, directory, false); return e },
	publish: func(from, to string) error {
		return windows.MoveFileEx(windows.StringToUTF16Ptr(from), windows.StringToUTF16Ptr(to), windows.MOVEFILE_WRITE_THROUGH)
	},
}

func releaseInventory(p string) (map[string]string, error) {
	return installationReleaseFiles.inventory(p)
}
func installationFileHash(p string) (string, error) { return installationReleaseFiles.hash(p) }
func copyInstallationFile(a, b, h string) error     { return installationReleaseFiles.copy(a, b, h) }
func writeInstallationContent(p, h string, open func() (io.ReadCloser, error)) error {
	return installationReleaseFiles.write(p, h, open)
}
func cleanInstallationPartials(a, b string, inv map[string]string) error {
	return installationReleaseFiles.cleanPartials(a, b, inv)
}
func copyReleaseFiles(a, b string, inv map[string]string) error {
	return installationReleaseFiles.clone(a, b, inv)
}
func verifyReleaseFiles(p string, inv map[string]string, partial bool) error {
	return installationReleaseFiles.verify(p, inv, partial)
}
func osMkdirRelease(p string) error { return installationReleaseFiles.mkdir(p) }
func removeReleaseFiles(p string, inv map[string]string) error {
	return installationReleaseFiles.remove(p, inv)
}

func writeInstallationJSON(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil || len(b) > 32768 {
		return fmt.Errorf("INSTALL_RECORD_INVALID")
	}
	if _, e = coreProtectedRead(path, false, false); e != nil && !os.IsNotExist(e) && e != windows.ERROR_FILE_NOT_FOUND {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	temp := path + ".tmp"
	if _, err := os.Lstat(temp); err == nil {
		if err = installationReleaseFiles.prefix(temp, func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }); err != nil {
			return err
		}
		if err = os.Remove(temp); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(temp), windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return fmt.Errorf("INSTALL_RECORD_WRITE_PENDING: %w", e)
	}
	f := os.NewFile(uintptr(h), temp)
	if f == nil {
		windows.CloseHandle(h)
		return fmt.Errorf("INSTALL_RECORD_HANDLE_FAILED")
	}
	defer os.Remove(temp)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	return windows.MoveFileEx(windows.StringToUTF16Ptr(temp), windows.StringToUTF16Ptr(path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func (o *nativeInstallation) Save(t InstallationTransaction) error {
	phase := t.Phase
	installationProgressPhase.Store(&phase)
	if e := validateInstallationTransaction(t); e != nil {
		return e
	}
	return writeInstallationJSON(filepath.Join(o.state, InstallationTransactionName), t)
}
func (o *nativeInstallation) Verify(t InstallationTransaction) error {
	disk, ok, e := readInstallationTransaction()
	if e != nil || !ok || !reflect.DeepEqual(disk, t) {
		return fmt.Errorf("INSTALL_RECORD_CHANGED")
	}
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil || u.User.Sid.String() != t.OwnerSID {
		return fmt.Errorf("INSTALL_OWNER_CHANGED")
	}
	if transition, pending, err := readCoreTransition(); err != nil {
		return err
	} else if pending {
		allowedSource := func(b CoreServiceBinding) bool {
			if b == (CoreServiceBinding{1, ProductID, t.OwnerSID, filepath.Join(o.app, BinaryName), t.Next.SHA}) {
				return true
			}
			if t.Previous == nil {
				return false
			}
			backup := *t.Previous
			backup.Executable = filepath.Join(o.previous, BinaryName)
			return b == *t.Previous || b == backup
		}
		if !allowedSource(transition.Next) || transition.Previous != nil && !allowedSource(*transition.Previous) {
			return fmt.Errorf("INSTALL_SERVICE_TRANSITION_CHANGED")
		}
		if e = recoverCoreServiceTransition(); e != nil {
			return e
		}
	}
	if t.Phase == InstallStaged || t.Phase == InstallQuiescing {
		if e = verifyReleaseFiles(o.candidate, t.NextFiles, false); e != nil {
			return e
		}
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, b, e := ownedCoreService(m)
	if t.Previous == nil && e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return nil
	}
	if e != nil {
		return e
	}
	defer s.Close()
	allowed := b == CoreServiceBinding{1, ProductID, t.OwnerSID, filepath.Join(o.app, BinaryName), t.Next.SHA}
	if t.Previous != nil {
		prev := *t.Previous
		backup := prev
		backup.Executable = filepath.Join(o.previous, BinaryName)
		allowed = allowed || b == prev || b == backup
	}
	if !allowed {
		return fmt.Errorf("INSTALL_SERVICE_CHANGED")
	}
	return nil
}
func (o *nativeInstallation) Quiesce(ctx context.Context, t InstallationTransaction) error {
	if t.Previous == nil {
		return nil
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	b, e := CurrentCoreBinding()
	if e != nil {
		return e
	}
	backup := *t.Previous
	backup.Executable = filepath.Join(o.previous, BinaryName)
	if b != *t.Previous && b != backup {
		return fmt.Errorf("INSTALL_SERVICE_CHANGED")
	}
	if b == *t.Previous {
		if e = closeInstallationLoginClients(ctx, b); e != nil {
			return e
		}
	}
	return StopExpectedCoreService(b)
}

func (o *nativeInstallation) BindPrevious(t InstallationTransaction) error {
	if t.Previous != nil {
		if e := copyReleaseFiles(filepath.Dir(t.Previous.Executable), o.previous, t.PreviousFiles); e != nil {
			return e
		}
		if e := bindCoreService(filepath.Join(o.previous, BinaryName), nil, "", false); e != nil {
			return e
		}
	}
	if e := migrateInstallationState(o.state); e != nil {
		return e
	}
	return migrateInstallationSecurity(o.state)
}
func migrateInstallationState(state string) error {
	old, e := coreStateDirectory()
	if e != nil {
		return e
	}
	if strings.EqualFold(old, state) {
		return nil
	}
	for _, name := range []string{coreBindingFile, "connection-preferences.json"} {
		path := filepath.Join(old, name)
		b, e := coreProtectedReadBounded(path, false, true, 32768)
		if os.IsNotExist(e) || e == windows.ERROR_FILE_NOT_FOUND {
			continue
		}
		if e != nil {
			return e
		}
		dest := filepath.Join(state, name)
		if _, e = os.Lstat(dest); e == nil {
			return fmt.Errorf("INSTALL_STATE_CONFLICT")
		} else if !os.IsNotExist(e) {
			return e
		}
		if e = writeInstallationJSON(dest, json.RawMessage(b)); e != nil {
			return e
		}
	}
	return nil
}
func (o *nativeInstallation) Publish(t InstallationTransaction) error {
	if e := cleanInstallationPartials(o.candidate, o.app, t.NextFiles); e != nil {
		return e
	}
	// Re-entering publication may find only some old files, no files, or some
	// next files. A mixed/foreign inventory is never silently overwritten.
	if e := verifyReleaseFiles(o.app, t.NextFiles, true); e != nil {
		if t.Previous == nil || !strings.EqualFold(filepath.Dir(t.Previous.Executable), o.app) {
			return e
		}
		deadline := time.Now().Add(20 * time.Second)
		for {
			err := removeReleaseFiles(o.app, t.PreviousFiles)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("INSTALL_FILES_IN_USE: %w", err)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	return copyReleaseFiles(o.candidate, o.app, t.NextFiles)
}

func (o *nativeInstallation) Start(t InstallationTransaction) error {
	exe := filepath.Join(o.app, BinaryName)
	if e := bindCoreService(exe, nil, "", false); e != nil {
		return e
	}
	if e := SetStartupContext(context.Background(), t.StartupEnabled, exe); e != nil {
		return e
	}
	if e := Register(exe, t.Next.Version); e != nil {
		return e
	}
	if e := UpdateShortcut(exe, false); e != nil {
		return e
	}
	if e := SetCoreAutomatic(t.StartupEnabled); e != nil {
		return e
	}
	return StartCoreService()
}
func (o *nativeInstallation) AwaitAcceptance(ctx context.Context, t InstallationTransaction) error {
	wait, stop := context.WithTimeout(ctx, 90*time.Second)
	defer stop()
	for wait.Err() == nil {
		b, e := coreProtectedRead(filepath.Join(o.state, installationReadyName), false, true)
		var r installationReady
		if e == nil && json.Unmarshal(b, &r) == nil && r.Product == ProductID && r.SHA256 == t.Next.SHA && installationReadyProcess(r) {
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-wait.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return fmt.Errorf("INSTALL_CORE_INITIALIZATION_NOT_ACCEPTED: %w", wait.Err())
}
func (o *nativeInstallation) Cleanup(t InstallationTransaction) error {
	if e := verifyReleaseFiles(o.app, t.NextFiles, false); e != nil {
		return e
	}
	if e := removeReleaseFiles(o.candidate, t.NextFiles); e != nil {
		return e
	}
	if t.Previous != nil {
		if e := removeReleaseFiles(o.previous, t.PreviousFiles); e != nil {
			return e
		}
	}
	if t.Previous != nil {
		root, e := protectedRoot(false)
		if e != nil {
			return e
		}
		path := filepath.Join(root, coreBindingFile)
		if raw, e := coreProtectedRead(path, false, true); e == nil {
			old, err := parseCoreBinding(raw)
			backup := *t.Previous
			backup.Executable = filepath.Join(o.previous, BinaryName)
			if err != nil || old != backup && old != *t.Previous {
				return fmt.Errorf("INSTALL_LEGACY_BINDING_CHANGED")
			}
			if e = os.Remove(path); e != nil {
				return e
			}
		} else if !os.IsNotExist(e) && e != windows.ERROR_FILE_NOT_FOUND {
			return e
		}
	}
	// Legacy files are pruned by the existing dependency-aware cleanup after
	// startup tasks have moved. It never removes referenced or unknown content.
	return nil
}
func (o *nativeInstallation) Restore(t InstallationTransaction) error {
	if e := o.Verify(t); e != nil {
		return e
	}
	current, found, e := readCoreBinding()
	if e != nil {
		return e
	}
	if found {
		if e = StopExpectedCoreService(current); e != nil {
			return e
		}
	}
	if t.Previous == nil {
		if e = cleanInstallationPartials(o.candidate, o.app, t.NextFiles); e != nil {
			return e
		}
		if found {
			if e = RemoveExpectedCoreService(current); e != nil {
				return e
			}
		}
		exe := filepath.Join(o.app, BinaryName)
		if Verify(exe) == nil {
			if e = UpdateShortcut(exe, true); e != nil {
				return e
			}
			if e = SetStartupContext(context.Background(), false, exe); e != nil {
				return e
			}
			if e = removeExactRegistration(exe); e != nil {
				return e
			}
		}
		if e = removeReleaseFiles(o.app, t.NextFiles); e != nil {
			return e
		}
		return removeReleaseFiles(o.candidate, t.NextFiles)
	}
	old := *t.Previous
	if err := cleanInstallationPartials(o.candidate, o.app, t.NextFiles); err != nil {
		if err = cleanInstallationPartials(o.previous, o.app, t.PreviousFiles); err != nil {
			return err
		}
	}
	backup := old
	backup.Executable = filepath.Join(o.previous, BinaryName)
	if strings.EqualFold(filepath.Dir(old.Executable), o.app) && verifyReleaseFiles(o.app, t.PreviousFiles, false) != nil {
		// A failed quiesce/bind has not published anything. A partial old App uses
		// the full proven backup; a partial next App is removed by its own inventory.
		if e = verifyReleaseFiles(o.previous, t.PreviousFiles, false); e != nil {
			return e
		}
		if current != backup {
			if e = bindCoreService(backup.Executable, nil, "", false); e != nil {
				return e
			}
		}
		if verifyReleaseFiles(o.app, t.NextFiles, true) == nil {
			e = removeReleaseFiles(o.app, t.NextFiles)
		} else {
			e = removeReleaseFiles(o.app, t.PreviousFiles)
		}
		if e != nil {
			return e
		}
		if e = copyReleaseFiles(o.previous, o.app, t.PreviousFiles); e != nil {
			return e
		}
	}

	if e = bindCoreService(old.Executable, nil, "", false); e != nil {
		return e
	}
	// An old release still reads its original Program Files metadata. Keep that
	// exact binding in sync before restarting it; protected state is retained.
	if filepath.Base(filepath.Dir(old.Executable)) != CurrentApplicationDirectory {
		root, e := protectedRoot(false)
		if e != nil {
			return e
		}
		nextSecurity := filepath.Join(o.state, "security")
		oldSecurity := filepath.Join(root, "security")
		if _, se := os.Lstat(nextSecurity); se == nil {
			if _, oe := os.Lstat(oldSecurity); !os.IsNotExist(oe) {
				return fmt.Errorf("INSTALL_SECURITY_ROLLBACK_CONFLICT")
			}
			if se = windows.MoveFileEx(windows.StringToUTF16Ptr(nextSecurity), windows.StringToUTF16Ptr(oldSecurity), windows.MOVEFILE_WRITE_THROUGH); se != nil {
				return se
			}
		}
		if e = writeInstallationJSON(filepath.Join(root, coreBindingFile), old); e != nil {
			return e
		}
	}
	r, e := readReceipt(filepath.Dir(old.Executable))
	if e != nil {
		return e
	}
	if e = Register(old.Executable, r.Version); e != nil {
		return e
	}
	if e = UpdateShortcut(old.Executable, false); e != nil {
		return e
	}
	if e = SetStartupContext(context.Background(), t.StartupEnabled, old.Executable); e != nil {
		return e
	}
	if t.PreviousStartType != 0 {
		if e = SetCoreAutomatic(t.PreviousStartType == 2); e != nil {
			return e
		}
	}
	if e = StartCoreService(); e != nil {
		return e
	}
	if !strings.EqualFold(filepath.Dir(old.Executable), o.app) {
		if e = removeReleaseFiles(o.app, t.NextFiles); e != nil {
			return e
		}
	}
	if e = cleanInstallationPartials(filepath.Dir(old.Executable), o.previous, t.PreviousFiles); e != nil {
		return e
	}
	if e = removeReleaseFiles(o.candidate, t.NextFiles); e != nil {
		return e
	}
	return removeReleaseFiles(o.previous, t.PreviousFiles)
}

// Only the authenticated SYSTEM core writes this acceptance, after original
// network/USB recovery and settings initialization, not merely SCM Running.
func AcceptInstallationReady() error {
	token := windows.GetCurrentProcessToken()
	u, e := token.GetTokenUser()
	if e != nil || !u.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return fmt.Errorf("INSTALL_ACCEPT_SYSTEM_REQUIRED")
	}
	t, present, e := readInstallationTransaction()
	if e != nil || !present {
		return e
	}
	if t.Phase != InstallPublished && t.Phase != InstallStarted {
		return nil
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	b, e := CurrentCoreBinding()
	if e != nil || !strings.EqualFold(b.Executable, self) || b.SHA256 != t.Next.SHA {
		return fmt.Errorf("INSTALL_ACCEPT_SOURCE_CHANGED")
	}
	if e = VerifyCoreServiceProcess(uint32(os.Getpid())); e != nil {
		return e
	}
	state, e := StateDirectory()
	if e != nil {
		return e
	}
	created, e := processCreation(uint32(os.Getpid()))
	if e != nil {
		return e
	}
	return writeInstallationJSON(filepath.Join(state, installationReadyName), installationReady{ProductID, t.Next.SHA, uint32(os.Getpid()), created})
}

func migrateInstallationSecurity(state string) error {
	root, e := protectedRoot(false)
	if e != nil {
		return e
	}
	old := filepath.Join(root, "security")
	next := filepath.Join(state, "security")
	if _, e = os.Lstat(old); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	if _, e = os.Lstat(next); e == nil {
		return fmt.Errorf("INSTALL_SECURITY_CONFLICT")
	} else if !os.IsNotExist(e) {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if e != nil {
		return e
	}
	actual, e := windows.GetNamedSecurityInfo(old, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil || !sameACL(actual, sd) || noReparse(old) != nil {
		return fmt.Errorf("INSTALL_SECURITY_UNPROVEN")
	}
	// Existing policy writers only use these product records; unknown additions
	// require inspection and stay at their original location.
	known := map[string]bool{"native-smb.json": true, "native-smb-acls.json": true, "native-smb-guest.json": true, "native-smb-account.json": true, "native-smb-account-rename.json": true, "shared-folders.json": true, "policy.json": true, "usb-devices.json": true, "firewall.json": true, "device-policy.json": true, "usb-gateway.json": true, "application-firewall.json": true, "usb-device-policy.json": true}
	entries, e := os.ReadDir(old)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if entry.IsDir() || !known[entry.Name()] {
			return fmt.Errorf("INSTALL_UNKNOWN_SECURITY_DATA_PRESERVED: %s", entry.Name())
		}
		if _, e = coreProtectedRead(filepath.Join(old, entry.Name()), false, false); e != nil {
			return e
		}
	}
	return windows.MoveFileEx(windows.StringToUTF16Ptr(old), windows.StringToUTF16Ptr(next), windows.MOVEFILE_WRITE_THROUGH)
}

func plannedInstallationInventory(next Receipt, archive io.ReaderAt, size int64) (map[string]string, error) {
	z, e := zip.NewReader(archive, size)
	if e != nil {
		return nil, e
	}
	index, present, e := embeddedDesktopIndex(z)
	if e != nil || !present {
		return nil, fmt.Errorf("INSTALL_PUBLISHER_DESKTOP_INDEX_REQUIRED: %v", e)
	}
	receipt, _ := json.Marshal(next)
	h := sha256.Sum256(receipt)
	inv := map[string]string{BinaryName: next.SHA, "ownership.json": hex.EncodeToString(h[:])}
	for name, h := range index {
		inv["Desktop/"+name] = hex.EncodeToString(h[:])
	}
	return inv, nil
}
func stageInstallationRelease(o *nativeInstallation, t InstallationTransaction, self string, archive io.ReaderAt, size int64) error {
	want, e := plannedInstallationInventory(t.Next, archive, size)
	if e != nil || !reflect.DeepEqual(want, t.NextFiles) {
		return fmt.Errorf("INSTALL_STAGED_PAYLOAD_CHANGED")
	}
	if e = osMkdirRelease(o.candidate); e != nil {
		return e
	}
	if e = writeInstallationContent(filepath.Join(o.candidate, BinaryName), t.Next.SHA, func() (io.ReadCloser, error) {
		if e := noReparse(self); e != nil {
			return nil, e
		}
		return os.Open(self)
	}); e != nil {
		return e
	}
	receipt, _ := json.Marshal(t.Next)
	if e = writeInstallationContent(filepath.Join(o.candidate, "ownership.json"), t.NextFiles["ownership.json"], func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(receipt)), nil }); e != nil {
		return e
	}
	dir := filepath.Join(o.candidate, "Desktop")
	if e = osMkdirRelease(dir); e != nil {
		return e
	}
	z, e := zip.NewReader(archive, size)
	if e != nil {
		return e
	}
	for _, entry := range z.File {
		if e = writeInstallationContent(filepath.Join(dir, entry.Name), t.NextFiles["Desktop/"+entry.Name], entry.Open); e != nil {
			return e
		}
	}
	return verifyReleaseFiles(o.candidate, t.NextFiles, false)
}

func installationReadyProcess(r installationReady) bool {
	if r.Creation == 0 || VerifyCoreServiceProcess(r.PID) != nil {
		return false
	}
	creation, e := processCreation(r.PID)
	return e == nil && creation == r.Creation && VerifyCoreServiceProcess(r.PID) == nil
}

var installationProgressPhase atomic.Pointer[InstallationPhase]

func InstallationProgressText() string {
	phase := InstallStaged
	if p := installationProgressPhase.Load(); p != nil {
		phase = *p
	}
	switch phase {
	case InstallStaged:
		return "正在準備安裝檔案…\n原有程式與連線會保留到檔案核驗完成。"
	case InstallQuiescing:
		return "正在正常關閉舊介面與連線…"
	case InstallPreviousBound, InstallPublished:
		return "正在更新程式檔案…\n已保留本次更新的臨時恢復副本。"
	case InstallStarted:
		return "正在啟動並核驗新版本…"
	case InstallAccepted, InstallCleaning:
		return "新版本已完成初始化，正在清理舊程式檔案…"
	case InstallRestoring:
		return "更新未完成，正在恢復原有版本…\n請等候恢復結束。"
	case InstallRolledBack:
		return "已恢復原有版本。"
	case InstallComplete:
		return "安裝已完成。"
	}
	return "正在安裝 USB Link…"
}

func discardStagedInstallation(o *nativeInstallation, t InstallationTransaction, self string, archive io.ReaderAt, size int64) error {
	if t.Phase != InstallStaged {
		return fmt.Errorf("INSTALL_DISCARD_PHASE_CHANGED")
	}
	if e := cleanInstallationPartialsForPayload(o.candidate, t, self, archive, size); e != nil {
		return e
	}
	if e := removeReleaseFiles(o.candidate, t.NextFiles); e != nil {
		return e
	}
	t.Phase = InstallRolledBack
	return o.Save(t)
}
func cleanInstallationPartialsForPayload(dir string, t InstallationTransaction, self string, archive io.ReaderAt, size int64) error {
	clean := func(name string, open func() (io.ReadCloser, error)) error {
		path := filepath.Join(dir, filepath.FromSlash(name)) + ".part"
		if _, e := os.Lstat(path); os.IsNotExist(e) {
			return nil
		} else if e != nil {
			return e
		}
		if e := installationReleaseFiles.prefix(path, open); e != nil {
			return e
		}
		return os.Remove(path)
	}
	if e := clean(BinaryName, func() (io.ReadCloser, error) { return os.Open(self) }); e != nil {
		return e
	}
	receipt, _ := json.Marshal(t.Next)
	if e := clean("ownership.json", func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(receipt)), nil }); e != nil {
		return e
	}
	z, e := zip.NewReader(archive, size)
	if e != nil {
		return e
	}
	for _, entry := range z.File {
		if e = clean("Desktop/"+entry.Name, entry.Open); e != nil {
			return e
		}
	}
	return nil
}
