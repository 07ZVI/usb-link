package connectioninstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// There is one runnable application directory. Previous and candidate images
// are temporary, protected transaction resources, never parallel installations.
const CurrentApplicationDirectory = "App"
const InstallationTransactionName = "installation-transaction.json"

type Receipt struct {
	Product string `json:"product"`
	Version string `json:"version"`
	SHA     string `json:"sha256"`
}

type InstallationPhase string

const (
	InstallStaged        InstallationPhase = "staged"
	InstallQuiescing     InstallationPhase = "quiescing"
	InstallPreviousBound InstallationPhase = "previous-bound"
	InstallPublished     InstallationPhase = "published"
	InstallStarted       InstallationPhase = "started"
	InstallAccepted      InstallationPhase = "accepted"
	InstallCleaning      InstallationPhase = "cleaning"
	InstallComplete      InstallationPhase = "complete"
	InstallRestoring     InstallationPhase = "restoring"
	InstallRolledBack    InstallationPhase = "rolled-back"
)

type InstallationTransaction struct {
	Schema            int                 `json:"schema"`
	Product           string              `json:"product"`
	OwnerSID          string              `json:"owner_sid"`
	Phase             InstallationPhase   `json:"phase"`
	Next              Receipt             `json:"next"`
	Previous          *CoreServiceBinding `json:"previous,omitempty"`
	PreviousStartType uint32              `json:"previous_start_type,omitempty"`
	StartupEnabled    bool                `json:"startup_enabled"`
	// Paths are derived from known folders; no command or caller-selected path
	// is authorized by this record. This inventory supplies bounded cleanup.
	NextFiles     map[string]string `json:"next_files"`
	PreviousFiles map[string]string `json:"previous_files,omitempty"`
}

// InstallationPhaseActive reports whether an installer owns the core's
// lifecycle. Only a finished or rolled-back transaction hands it back.
func InstallationPhaseActive(p InstallationPhase) bool {
	return validInstallationPhase(p) && p != InstallComplete && p != InstallRolledBack
}

func validInstallationPhase(p InstallationPhase) bool {
	switch p {
	case InstallStaged, InstallQuiescing, InstallPreviousBound, InstallPublished, InstallStarted, InstallAccepted, InstallCleaning, InstallComplete, InstallRestoring, InstallRolledBack:
		return true
	}
	return false
}

func validInstallationHash(v string) bool {
	return len(v) == 64 && strings.Trim(v, "0123456789abcdef") == ""
}

func validateInstallationTransaction(t InstallationTransaction) error {
	if t.Schema != 1 || t.Product != ProductID || !validPreparedUserSID(t.OwnerSID) || !validInstallationPhase(t.Phase) || t.Next.Product != ProductID || !versionPattern.MatchString(t.Next.Version) || !validInstallationHash(t.Next.SHA) {
		return errors.New("INSTALL_TRANSACTION_INVALID")
	}
	if t.PreviousStartType != 0 && t.PreviousStartType != 2 && t.PreviousStartType != 3 {
		return errors.New("INSTALL_PREVIOUS_START_TYPE_INVALID")
	}
	if t.Previous != nil {
		b, e := json.Marshal(t.Previous)
		if e != nil {
			return e
		}
		if _, e = parseCoreBinding(b); e != nil || t.Previous.OwnerSID != t.OwnerSID {
			return errors.New("INSTALL_TRANSACTION_PREVIOUS_INVALID")
		}
	}
	for _, inventory := range []map[string]string{t.NextFiles, t.PreviousFiles} {
		if len(inventory) > 1024 {
			return errors.New("INSTALL_TRANSACTION_INVENTORY_LIMIT")
		}
		seen := map[string]bool{}
		for name, digest := range inventory {
			if len(name) > 256 || !safeInstallationFile(name) || !validInstallationHash(digest) || seen[strings.ToLower(name)] {
				return errors.New("INSTALL_TRANSACTION_INVENTORY_INVALID")
			}
			seen[strings.ToLower(name)] = true
		}
	}
	if t.NextFiles[BinaryName] != t.Next.SHA || len(t.NextFiles) < 2 || t.NextFiles["ownership.json"] == "" {
		return errors.New("INSTALL_TRANSACTION_NEXT_INCOMPLETE")
	}
	if t.Previous != nil && (t.PreviousFiles[BinaryName] != t.Previous.SHA256 || t.PreviousFiles["ownership.json"] == "") {
		return errors.New("INSTALL_TRANSACTION_PREVIOUS_INCOMPLETE")
	}
	if b, e := json.Marshal(t); e != nil || len(b) > 32768 {
		return errors.New("INSTALL_TRANSACTION_SIZE_LIMIT")
	}
	return nil
}

func safeInstallationFile(name string) bool {
	if name == BinaryName || name == "ownership.json" {
		return true
	}
	if !strings.HasPrefix(name, "Desktop/") {
		return false
	}
	leaf := strings.TrimPrefix(name, "Desktop/")
	return leaf != "" && leaf != "." && leaf != ".." && !strings.ContainsAny(leaf, "/\\:\x00") && !strings.HasSuffix(leaf, ".") && !strings.HasSuffix(leaf, " ")
}

// Native adapters must verify their exact source, ownership and expected SCM
// state on every operation. Resume never infers success from a directory name.
type InstallationOperations interface {
	Save(InstallationTransaction) error
	Verify(InstallationTransaction) error
	Quiesce(context.Context, InstallationTransaction) error
	BindPrevious(InstallationTransaction) error
	Publish(InstallationTransaction) error
	Start(InstallationTransaction) error
	AwaitAcceptance(context.Context, InstallationTransaction) error
	Cleanup(InstallationTransaction) error
	Restore(InstallationTransaction) error
}

// ExecuteInstallation retains its caller's native installer lease throughout.
// It records intent before mutations, resumes each idempotent phase, and keeps
// the previous image until an authenticated core accepts this exact release.
func ExecuteInstallation(ctx context.Context, t InstallationTransaction, ops InstallationOperations) (result InstallationTransaction, err error) {
	if ctx == nil || ops == nil {
		return t, errors.New("INSTALL_OPERATIONS_REQUIRED")
	}
	if e := validateInstallationTransaction(t); e != nil {
		return t, e
	}
	result = t
	set := func(p InstallationPhase) error {
		t.Phase = p
		if e := ops.Save(t); e != nil {
			return e
		}
		result = t
		return nil
	}
	step := func(action func() error) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := ops.Verify(t); e != nil {
			return e
		}
		return action()
	}
	// Once accepted, an interrupted cleanup resumes cleanup, never rolls a
	// successfully running release back merely because an old file was busy.
	if t.Phase == InstallAccepted || t.Phase == InstallCleaning {
		if e := set(InstallCleaning); e != nil {
			return result, e
		}
		if e := step(func() error { return ops.Cleanup(t) }); e != nil {
			return result, e
		}
		err = set(InstallComplete)
		return result, err
	}
	if t.Phase == InstallComplete || t.Phase == InstallRolledBack {
		return result, ops.Verify(t)
	}
	if t.Phase == InstallRestoring {
		if e := step(func() error { return ops.Restore(t) }); e != nil {
			return result, e
		}
		err = set(InstallRolledBack)
		return result, err
	}
	defer func() {
		if err == nil || t.Phase == InstallStaged || t.Phase == InstallAccepted || t.Phase == InstallCleaning || t.Phase == InstallComplete {
			return
		}
		// Native Restore remains ownership checked even when the user cancelled.
		// Persist restoration intent first; failed restoration preserves all proof.
		if e := set(InstallRestoring); e != nil {
			err = errors.Join(err, e)
			return
		}
		if e := ops.Restore(t); e != nil {
			err = errors.Join(err, fmt.Errorf("INSTALL_RESTORE_PENDING: %w", e))
			return
		}
		if e := set(InstallRolledBack); e != nil {
			err = errors.Join(err, e)
		}
	}()
	if t.Phase == InstallStaged {
		if e := step(func() error { return nil }); e != nil {
			return result, e
		}
		if e := set(InstallQuiescing); e != nil {
			return result, e
		}
	}
	if t.Phase == InstallQuiescing {
		if e := step(func() error { return ops.Quiesce(ctx, t) }); e != nil {
			return result, e
		}
		if e := step(func() error { return ops.BindPrevious(t) }); e != nil {
			return result, e
		}
		if e := set(InstallPreviousBound); e != nil {
			return result, e
		}
	}
	if t.Phase == InstallPreviousBound {
		if e := step(func() error { return ops.Publish(t) }); e != nil {
			return result, e
		}
		if e := set(InstallPublished); e != nil {
			return result, e
		}
	}
	if t.Phase == InstallPublished {
		if e := step(func() error { return ops.Start(t) }); e != nil {
			return result, e
		}
		if e := set(InstallStarted); e != nil {
			return result, e
		}
	}
	if t.Phase == InstallStarted {
		if e := step(func() error { return ops.AwaitAcceptance(ctx, t) }); e != nil {
			return result, e
		}
		if e := set(InstallAccepted); e != nil {
			return result, e
		}
	}
	if e := set(InstallCleaning); e != nil {
		return result, e
	}
	if e := step(func() error { return ops.Cleanup(t) }); e != nil {
		return result, e
	}
	err = set(InstallComplete)
	return result, err
}

func installationInventoriesEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for n, h := range a {
		if b[n] != h {
			return false
		}
	}
	return true
}
