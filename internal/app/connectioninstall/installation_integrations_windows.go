//go:build windows && amd64

package connectioninstall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/platform/windows/wincom"
)

// Never stat a path from task/shortcut metadata before checking its local scope.
// An intact but changed source is a conflict, not an orphan to be adopted.
func installationIntegrationSource(target string) (string, error) {
	root, e := Root()
	if e != nil {
		return "", e
	}
	legacy, e := legacyRoot()
	if e != nil {
		return "", e
	}
	historical := legacyIntegrationTarget(target, root, legacy)
	if !historical && !strings.EqualFold(target, filepath.Join(root, CurrentApplicationDirectory, BinaryName)) {
		return "", fmt.Errorf("INSTALL_INTEGRATION_TARGET_OUTSIDE_PRODUCT: %q", target)
	}
	if e := Verify(target); e == nil {
		return "verified", nil
	}
	if !historical {
		// A temporarily absent App during a protected transaction is handled by
		// that transaction's original verifier. This is read-only classification,
		// never deletion authority and never executable trust.
		t, present, err := readInstallationTransaction()
		if err == nil && present && t.Phase != InstallRolledBack {
			user, err := windows.GetCurrentProcessToken().GetTokenUser()
			if err == nil && t.OwnerSID == user.User.Sid.String() {
				dir := filepath.Dir(target)
				if verifyReleaseFiles(dir, t.NextFiles, true) == nil {
					return "transaction", nil
				}
				if t.Previous != nil && strings.EqualFold(t.Previous.Executable, target) && verifyReleaseFiles(dir, t.PreviousFiles, true) == nil {
					return "transaction", nil
				}
			}
		}
		return "", fmt.Errorf("INSTALL_INTEGRATION_CURRENT_SOURCE_UNVERIFIED: %q", target)
	}
	dir := filepath.Dir(target)
	parent := filepath.Dir(dir)
	// Both roots are children of the system Program Files folder. If the root
	// remains, its marker/ACL must still be ours; otherwise inspect its parent.
	if e := noReparse(filepath.Dir(parent)); e != nil {
		return "", e
	}
	if _, e := os.Lstat(parent); e == nil {
		if _, e := protectedRootAt(parent, false); e != nil {
			return "", e
		}
	} else if !os.IsNotExist(e) {
		return "", e
	}
	if _, e := os.Lstat(dir); os.IsNotExist(e) {
		return "orphan", nil
	} else if e != nil {
		return "", e
	}
	return "", fmt.Errorf("INSTALL_INTEGRATION_SOURCE_CHANGED: %q (version directory exists; preserving it)", target)
}

func withInstallationTaskFolder(fn func(*wincom.Dispatch, string, string) error) error {
	name, sid, e := taskIdentity()
	if e != nil {
		return e
	}
	return wincom.WithApartment(func() error {
		scheduler, e := wincom.Create("{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}")
		if e != nil {
			return e
		}
		defer scheduler.Close()
		v, e := scheduler.Call("Connect")
		v.Clear()
		if e != nil {
			return e
		}
		folder, e := nativeObject(scheduler, "GetFolder", true, wincom.String(`\`))
		if e != nil {
			return e
		}
		defer folder.Close()
		return fn(folder, name, sid)
	})
}

func inspectInstallationTasks(folder *wincom.Dispatch, name, sid string) ([]installationIntegration, error) {
	states := map[string]string{}
	var problems []error
	tasks, e := nativeProductTasksInspected(folder, name, sid, func(target string) error {
		state, e := installationIntegrationSource(target)
		states[target] = state
		if e != nil {
			problems = append(problems, e)
		}
		return e
	}, false, true)
	problems = append(problems, e)
	var out []installationIntegration
	for _, t := range tasks {
		v := installationTaskObservation(t, states[t.Command])
		if v.Problem != "" {
			problems = append(problems, fmt.Errorf("%s: %s", t.Name, v.Problem))
		}
		out = append(out, v)
	}
	return out, errors.Join(problems...)
}

func integrationShortcutBytes(path string) ([]byte, error) {
	if e := noReparse(filepath.Dir(path)); e != nil {
		return nil, e
	}
	if e := noReparse(path); e != nil {
		return nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() == 0 || st.Size() > 16384 {
		return nil, errors.New("INSTALL_SHORTCUT_SIZE_INVALID")
	}
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) != st.Size() {
		return nil, errors.New("INSTALL_SHORTCUT_READ_CHANGED")
	}
	return b, nil
}

func inspectInstallationShortcut(shell *wincom.Dispatch, path string) (installationIntegration, bool, error) {
	return inspectInstallationShortcutWithSource(shell, path, installationIntegrationSource)
}

func inspectInstallationShortcutWithSource(shell *wincom.Dispatch, path string, source func(string) (string, error)) (installationIntegration, bool, error) {
	v := installationIntegration{Kind: "shortcut", Name: path}
	b, e := integrationShortcutBytes(path)
	if os.IsNotExist(e) {
		return v, false, nil
	}
	if e != nil {
		return v, true, e
	}
	v.Content = b
	link, e := nativeObject(shell, "CreateShortcut", true, wincom.String(path))
	if e != nil {
		return v, true, e
	}
	defer link.Close()
	v.Target, e = nativeString(link, "TargetPath")
	if e != nil {
		return v, true, e
	}
	arguments, e := nativeString(link, "Arguments")
	if e != nil {
		return v, true, e
	}
	if arguments != "" {
		return v, true, errors.New("INSTALL_SHORTCUT_ARGUMENTS_CHANGED")
	}
	v.State, e = source(v.Target)
	if e != nil {
		return v, true, e
	}
	after, e := integrationShortcutBytes(path)
	if e != nil || !bytes.Equal(after, b) {
		return v, true, errors.New("INSTALL_SHORTCUT_CHANGED_DURING_QUERY")
	}
	return v, true, nil
}

func installationShortcutPaths() ([]string, error) {
	programs, e := UserKnownFolderPath(windows.FOLDERID_Programs, 0)
	if e != nil {
		return nil, e
	}
	if e := noReparse(programs); e != nil {
		return nil, e
	}
	return []string{filepath.Join(programs, "USB Link.lnk"), filepath.Join(programs, "隨航 USB — iPad.lnk")}, nil
}

// Queries are independent: a task failure does not hide shortcut problems.
func inspectInstallationIntegrations() ([]installationIntegration, error) {
	var out []installationIntegration
	taskError := withInstallationTaskFolder(func(folder *wincom.Dispatch, name, sid string) error {
		tasks, e := inspectInstallationTasks(folder, name, sid)
		out = append(out, tasks...)
		return e
	})
	shortcutError := wincom.WithApartment(func() error {
		paths, e := installationShortcutPaths()
		if e != nil {
			return e
		}
		shell, e := wincom.Create("{72C24DD5-D70A-438B-8A42-98424B88AFB8}")
		if e != nil {
			return e
		}
		defer shell.Close()
		var problems []error
		for _, path := range paths {
			v, present, e := inspectInstallationShortcut(shell, path)
			if e != nil {
				v.Problem = e.Error()
				problems = append(problems, fmt.Errorf("%s: %w", path, e))
			}
			if present {
				out = append(out, v)
			}
		}
		return errors.Join(problems...)
	})
	return out, errors.Join(taskError, shortcutError)
}

func backupInstallationIntegration(v installationIntegration) error {
	state, e := StateDirectory()
	if e != nil {
		return e
	}
	dir, e := protectedRootAt(filepath.Join(state, "IntegrationRecovery"), true)
	if e != nil {
		return e
	}
	// Raw task XML / shortcut bytes are saved, but never executed or imported.
	record := struct {
		Product, Kind, Name, Target, XML string
		Content                          []byte
	}{ProductID, v.Kind, v.Name, v.Target, v.XML, v.Content}
	b, e := json.Marshal(record)
	if e != nil || len(b) > 32768 {
		return errors.New("INSTALL_INTEGRATION_BACKUP_TOO_LARGE")
	}
	sum := sha256.Sum256(b)
	path := filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
	if old, e := coreProtectedReadBounded(path, false, true, 32768); e == nil {
		if bytes.Equal(old, b) {
			return nil
		}
		return errors.New("INSTALL_INTEGRATION_BACKUP_CHANGED")
	} else if !os.IsNotExist(e) {
		return e
	}
	if e := writeInstallationJSON(path, record); e != nil {
		return e
	}
	after, e := coreProtectedReadBounded(path, false, true, 32768)
	if e != nil || !bytes.Equal(after, b) {
		return errors.New("INSTALL_INTEGRATION_BACKUP_READBACK_FAILED")
	}
	return nil
}

func sameInstallationIntegration(a, b installationIntegration) bool {
	return a.Kind == b.Kind && a.Name == b.Name && a.Target == b.Target && a.State == b.State && a.XML == b.XML && bytes.Equal(a.Content, b.Content) && b.Problem == ""
}

func recheckInstallationIntegration(want installationIntegration, remove bool) error {
	if want.Kind == "task" {
		return withInstallationTaskFolder(func(folder *wincom.Dispatch, name, sid string) error {
			all, e := inspectInstallationTasks(folder, name, sid)
			if e != nil {
				return e
			}
			for _, got := range all {
				if got.Name != want.Name {
					continue
				}
				if !sameInstallationIntegration(want, got) {
					return errors.New("INSTALL_TASK_CHANGED_AFTER_BACKUP")
				}
				if !remove {
					return nil
				}
				v, e := folder.Call("DeleteTask", wincom.String(want.Name), wincom.Int(0))
				v.Clear()
				if e != nil {
					return e
				}
				after, e := inspectInstallationTasks(folder, name, sid)
				if e != nil {
					return e
				}
				for _, a := range after {
					if a.Name == want.Name {
						return errors.New("INSTALL_TASK_DELETE_READBACK_FAILED")
					}
				}
				return nil
			}
			return errors.New("INSTALL_TASK_DISAPPEARED_AFTER_BACKUP")
		})
	}
	return wincom.WithApartment(func() error {
		shell, e := wincom.Create("{72C24DD5-D70A-438B-8A42-98424B88AFB8}")
		if e != nil {
			return e
		}
		defer shell.Close()
		got, present, e := inspectInstallationShortcut(shell, want.Name)
		if e != nil {
			return e
		}
		if !present || !sameInstallationIntegration(want, got) {
			return errors.New("INSTALL_SHORTCUT_CHANGED_AFTER_BACKUP")
		}
		if !remove {
			return nil
		}
		if e := os.Remove(want.Name); e != nil {
			return e
		}
		if _, e := os.Lstat(want.Name); !os.IsNotExist(e) {
			return errors.New("INSTALL_SHORTCUT_DELETE_READBACK_FAILED")
		}
		return nil
	})
}

// Runs only from the elevated installer while it holds installation and SCM
// leases. Ordinary startup verification keeps its original fail-closed policy.
func repairOrphanInstallationIntegrations() error {
	startupTaskLock.Lock()
	defer startupTaskLock.Unlock()
	all, e := inspectInstallationIntegrations()
	if e != nil {
		return e
	}
	var actions []integrationRecoveryAction
	for _, v := range all {
		if v.State != "orphan" {
			continue
		}
		actions = append(actions, integrationRecoveryAction{
			Backup:  func() error { return backupInstallationIntegration(v) },
			Recheck: func() error { return recheckInstallationIntegration(v, false) },
			Remove:  func() error { return recheckInstallationIntegration(v, true) },
		})
	}
	return recoverInstallationIntegrations(actions)
}

// Rollback owns only integrations pointing at the failed published App. A
// different historical target was not created by this transaction and remains.
func removeFailedInstallationIntegrations(exe string) error {
	startupTaskLock.Lock()
	defer startupTaskLock.Unlock()
	if e := Verify(exe); e != nil {
		return e
	}
	all, e := inspectInstallationIntegrations()
	if e != nil {
		return e
	}
	var actions []integrationRecoveryAction
	for _, v := range all {
		if !strings.EqualFold(v.Target, exe) {
			continue
		}
		actions = append(actions, integrationRecoveryAction{
			Backup:  func() error { return backupInstallationIntegration(v) },
			Recheck: func() error { return recheckInstallationIntegration(v, false) },
			Remove:  func() error { return recheckInstallationIntegration(v, true) },
		})
	}
	return recoverInstallationIntegrations(actions)
}
