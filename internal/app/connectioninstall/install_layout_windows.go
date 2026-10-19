//go:build windows && amd64

package connectioninstall

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Program files are immutable release content. Machine state and transactions
// survive replacing/deleting that directory, including SMB credentials/journals.
func MachineDataDirectory() (string, error) {
	deps, e := DependencyDirectory()
	if e != nil {
		return "", e
	}
	return filepath.Dir(deps), nil
}

func StateDirectory() (string, error) {
	base, e := MachineDataDirectory()
	if e != nil {
		return "", e
	}
	return protectedRootAt(filepath.Join(base, "State"), true)
}

func installationUpdatesDirectory() (string, error) {
	base, e := MachineDataDirectory()
	if e != nil {
		return "", e
	}
	return protectedRootAt(filepath.Join(base, "Updates"), true)
}

func CurrentApplication() (string, error) {
	root, e := Root()
	return filepath.Join(root, CurrentApplicationDirectory, BinaryName), e
}

// Until a verified old core is quiesced, legacy metadata stays at its original
// path so its own shutdown can still validate it. Native migration copies these
// exact files only under the installation/core leases, never by fallback guess.
func coreStateDirectory() (string, error) {
	data, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return "", e
	}
	state := filepath.Join(data, "USB Link", "State")
	if _, e = os.Lstat(filepath.Join(state, coreBindingFile)); e == nil {
		return protectedRootAt(state, false)
	} else if !os.IsNotExist(e) {
		return "", e
	}
	root, e := Root()
	if e != nil {
		return "", e
	}
	if _, e = os.Lstat(filepath.Join(root, coreBindingFile)); e == nil {
		return protectedRoot(false)
	} else if !os.IsNotExist(e) {
		return "", e
	}
	if _, e = os.Lstat(state); e == nil {
		return protectedRootAt(state, false)
	}
	if !os.IsNotExist(e) {
		return "", e
	}
	return StateDirectory()
}

func readInstallationTransaction() (InstallationTransaction, bool, error) {
	var t InstallationTransaction
	data, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return t, false, e
	}
	state := filepath.Join(data, "USB Link", "State")
	if _, e = os.Lstat(state); os.IsNotExist(e) {
		return t, false, nil
	}
	if e != nil {
		return t, false, e
	}
	if _, e = protectedRootAt(state, false); e != nil {
		return t, false, e
	}
	b, e := coreProtectedReadBounded(filepath.Join(state, InstallationTransactionName), false, true, 32768)
	if os.IsNotExist(e) || e == windows.ERROR_FILE_NOT_FOUND {
		return t, false, nil
	}
	if e != nil {
		return t, false, e
	}
	if !preparedJournalUnique(b) {
		return t, true, fmt.Errorf("INSTALL_TRANSACTION_INVALID")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&t); e != nil {
		return t, true, e
	}
	return t, true, validateInstallationTransaction(t)
}

// Scope is independently authenticated before a receipt is parsed. A generic
// App/Previous name outside these exact protected roots conveys no ownership.
func trustedCoreDirectory(dir string) (string, error) {
	root, e := Root()
	if e != nil {
		return "", e
	}
	old, e := legacyRoot()
	if e != nil {
		return "", e
	}
	parent := filepath.Dir(dir)
	name := filepath.Base(dir)
	if strings.EqualFold(parent, root) && (name == CurrentApplicationDirectory || versionPattern.MatchString(name)) {
		return protectedRootAt(root, false)
	}
	if strings.EqualFold(parent, old) && versionPattern.MatchString(name) {
		return protectedRootAt(old, false)
	}
	data, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return "", e
	}
	updates := filepath.Join(data, "USB Link", "Updates")
	if !strings.EqualFold(parent, updates) || name != "Candidate" && name != "Previous" {
		return "", fmt.Errorf("INSTALL_SOURCE_SCOPE_INVALID")
	}
	if _, e = protectedRootAt(filepath.Dir(updates), false); e != nil {
		return "", e
	}
	if _, e = protectedRootAt(updates, false); e != nil {
		return "", e
	}
	t, present, e := readInstallationTransaction()
	if e != nil || !present || t.Phase == InstallComplete || t.Phase == InstallRolledBack {
		return "", fmt.Errorf("INSTALL_TRANSACTION_SOURCE_UNPROVEN")
	}
	return updates, nil
}

func receiptDirectoryMatches(name, version string) bool {
	return name == version || name == CurrentApplicationDirectory || name == "Candidate" || name == "Previous"
}

func verifyTransactionCoreReceipt(dir string, r Receipt) error {
	if filepath.Base(dir) != "Candidate" && filepath.Base(dir) != "Previous" {
		return nil
	}
	t, present, e := readInstallationTransaction()
	if e != nil || !present {
		return fmt.Errorf("INSTALL_TRANSACTION_SOURCE_UNPROVEN")
	}
	if filepath.Base(dir) == "Previous" {
		if t.Previous == nil || r.SHA != t.Previous.SHA256 {
			return fmt.Errorf("INSTALL_PREVIOUS_SOURCE_CHANGED")
		}
	} else if r != t.Next {
		return fmt.Errorf("INSTALL_NEXT_SOURCE_CHANGED")
	}
	return nil
}

// UI clients release their image pins during an authenticated local update;
// otherwise an old client can hold the stable application file open forever.
func LocalInstallationDraining(exe string) bool {
	t, present, e := readInstallationTransaction()
	if e != nil || !present || t.Previous == nil || !strings.EqualFold(t.Previous.Executable, exe) {
		return false
	}
	switch t.Phase {
	case InstallQuiescing, InstallPreviousBound, InstallPublished, InstallStarted, InstallRestoring:
	default:
		return false
	}
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil || u.User.Sid.String() != t.OwnerSID {
		return false
	}
	hash, e := fileHash(exe)
	return e == nil && hash == t.Previous.SHA256
}

// LocalInstallationActive is the explicit "installer owns the core" signal for
// this user: an unfinished installation transaction. A UI must neither start
// nor stop the core service while it is true, whichever version is installing.
func LocalInstallationActive() bool {
	t, present, e := readInstallationTransaction()
	if e != nil || !present {
		return e != nil && present // An unreadable, present journal is not proof of absence.
	}
	u, ue := windows.GetCurrentProcessToken().GetTokenUser()
	if ue != nil || u.User.Sid.String() != t.OwnerSID {
		return false
	}
	return InstallationPhaseActive(t.Phase)
}

// CoreServiceTransitioning reports a start or stop already in progress; the
// service is then being driven deliberately by someone else.
func CoreServiceTransitioning() bool {
	m, e := mgr.Connect()
	if e != nil {
		return false
	}
	defer m.Disconnect()
	s, _, e := ownedCoreService(m)
	if e != nil {
		return false
	}
	defer s.Close()
	state, e := s.Query()
	return e == nil && (state.State == svc.StopPending || state.State == svc.StartPending)
}
