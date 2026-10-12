package connectioninstall

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestRollbackAndIncompletePhasesCannotReportInstalled(t *testing.T) {
	for _, p := range []InstallationPhase{InstallStaged, InstallQuiescing, InstallPreviousBound, InstallPublished, InstallStarted, InstallAccepted, InstallCleaning, InstallRestoring, InstallRolledBack} {
		if installationOutcomeError(InstallationTransaction{Phase: p}) == nil {
			t.Fatal(p)
		}
	}
	if installationOutcomeError(InstallationTransaction{Phase: InstallComplete}) != nil {
		t.Fatal("completed install rejected")
	}
	for _, previous := range []*CoreServiceBinding{nil, {}} {
		e := installationOutcomeError(InstallationTransaction{Phase: InstallRolledBack, Previous: previous})
		if strings.Contains(e.Error(), "INSTALL_PREVIOUS_VERSION_RESTORED") != (previous != nil) {
			t.Fatal("fresh install rollback claimed an old version exists", previous, e)
		}
	}
}
func TestSamePackageReinstallRequiresEveryUninstallAbsence(t *testing.T) {
	for bad := -1; bad < 4; bad++ {
		var probes [4]func() (bool, error)
		for i := range probes {
			present := i == bad
			probes[i] = func() (bool, error) { return present, nil }
		}
		clean, e := cleanCompletedUninstall(InstallComplete, cleanUninstallProbes{probes[0], probes[1], probes[2], probes[3]})
		if e != nil || clean != (bad < 0) {
			t.Fatalf("present=%d clean=%v error=%v", bad, clean, e)
		}
	}
	absent := func() (bool, error) { return false, nil }
	for _, phase := range []InstallationPhase{InstallStaged, InstallRestoring, InstallRolledBack} {
		if clean, _ := cleanCompletedUninstall(phase, cleanUninstallProbes{absent, absent, absent, absent}); clean {
			t.Fatal("nonterminal/rollback journal used as uninstall", phase)
		}
	}
	refused := errors.New("query denied")
	denied := func() (bool, error) { return false, refused }
	if clean, e := cleanCompletedUninstall(InstallComplete, cleanUninstallProbes{absent, absent, denied, absent}); clean || !errors.Is(e, refused) {
		t.Fatal(clean, e)
	}
	if _, e := cleanCompletedUninstall(InstallComplete, cleanUninstallProbes{absent, nil, absent, absent}); e == nil {
		t.Fatal("missing proof accepted")
	}
}

func TestMatchingFilesCannotSkipMetadataStartOrInitialization(t *testing.T) {
	for _, fail := range []string{"verify", "metadata", "start", "await", ""} {
		var calls []string
		rejected := errors.New("not ready")
		step := func(name string) error {
			calls = append(calls, name)
			if name == fail {
				return rejected
			}
			return nil
		}
		e := confirmCompletedReinstall(context.Background(), InstallComplete, completedReinstallActions{
			Verify: func() error { return step("verify") }, Metadata: func() error { return step("metadata") }, Start: func() error { return step("start") }, Await: func(context.Context) error { return step("await") },
		})
		want := []string{"verify", "metadata", "start", "await"}
		if fail != "" {
			for i, n := range want {
				if n == fail {
					want = want[:i+1]
					break
				}
			}
		}
		if !reflect.DeepEqual(calls, want) || (fail != "" && !errors.Is(e, rejected)) || fail == "" && e != nil {
			t.Fatal(fail, calls, e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	step := func() error { called = true; return nil }
	if e := confirmCompletedReinstall(ctx, InstallComplete, completedReinstallActions{step, step, step, nil}); !errors.Is(e, context.Canceled) || called {
		t.Fatal("cancelled repeat install mutated state", e)
	}
}
