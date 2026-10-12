package connectioninstall

import (
	"errors"
	"strings"

	"suhang/usbnet/internal/app/remoteupdate"
)

type installationIntegration struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Target  string `json:"target"`
	State   string `json:"state"`
	Problem string `json:"problem,omitempty"`
	XML     string `json:"-"`
	Content []byte `json:"-"`
}

func installationTaskObservation(t nativeStartupTask, state string) installationIntegration {
	v := installationIntegration{Kind: "task", Name: t.Name, Target: t.Command, State: state, XML: t.XML, Problem: t.InspectionProblem}
	if v.Problem == "" && state == "orphan" && (!nativeHistoricalTaskShape(t.XML) || len(t.XML) > 16384 || t.State == 4 || t.State == 2) {
		v.Problem = "INSTALL_ORPHAN_TASK_ACTIVE_OR_CHANGED"
	}
	return v
}

// This is deletion authority only. A missing historical version directory never
// becomes a trusted executable, and App/Candidate/Previous are not legacy paths.
func legacyIntegrationTarget(target, root, legacy string) bool {
	clean := func(s string) string { return strings.ReplaceAll(s, `\`, "/") }
	p := clean(target)
	for _, scope := range []struct{ root, binary string }{{root, BinaryName}, {legacy, LegacyBinaryName}} {
		r := clean(scope.root)
		if len(p) <= len(r)+1 || !strings.EqualFold(p[:len(r)+1], r+"/") {
			continue
		}
		parts := strings.Split(p[len(r)+1:], "/")
		if len(parts) == 2 && versionPattern.MatchString(parts[0]) && parts[1] == scope.binary {
			return true
		}
	}
	return false
}

// A newer installer may finish deletion-only rollback of a failed FIRST
// installation. It may not resume publication or execute the old candidate.
// The native adapter still checks the protected journal, owner, SCM and every
// file against the OLD inventory. No old hash is replaced with the new hash.
func canFinishInstallationRollback(t InstallationTransaction, owner, version string) bool {
	return validateInstallationTransaction(t) == nil && t.OwnerSID == owner &&
		t.Phase == InstallRestoring && t.Previous == nil && len(t.PreviousFiles) == 0 &&
		remoteupdate.Newer(version, t.Next.Version)
}

type integrationRecoveryAction struct {
	Backup, Recheck, Remove func() error
}

// All independent checks/backups complete before the first deletion. A fresh
// check is also required immediately before each removal; partial completion
// can be retried from the remaining live objects and durable backups.
func recoverInstallationIntegrations(actions []integrationRecoveryAction) error {
	var problems []error
	for _, a := range actions {
		problems = append(problems, a.Recheck())
	}
	if e := errors.Join(problems...); e != nil {
		return e
	}
	for _, a := range actions {
		if e := a.Backup(); e != nil {
			return e
		}
	}
	for _, a := range actions {
		if e := a.Recheck(); e != nil {
			return e
		}
	}
	for _, a := range actions {
		if e := a.Recheck(); e != nil {
			return e
		}
		if e := a.Remove(); e != nil {
			return e
		}
	}
	return nil
}
