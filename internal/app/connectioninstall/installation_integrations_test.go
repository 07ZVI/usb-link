package connectioninstall

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestInstallationTaskProblemsStayWithTheirOwnTask(t *testing.T) {
	sid := "S-1-5-21-1-2-3-4"
	target := `C:\Program Files\USB Link\0.8.97\USB-Link.exe`
	x, err := TaskXML(target, sid)
	if err != nil {
		t.Fatal(err)
	}
	good := nativeStartupTask{Name: "current", Command: target, XML: x, State: 3}
	bad := good
	bad.Name = "legacy"
	bad.InspectionProblem = "STARTUP_TASK_TRIGGER_CHANGED"
	for _, state := range []string{"verified", "orphan"} {
		failed := installationTaskObservation(bad, state)
		passed := installationTaskObservation(good, state)
		if failed.Problem != bad.InspectionProblem || passed.Problem != "" {
			t.Fatalf("task errors conflated: failed=%+v passed=%+v", failed, passed)
		}
	}
	for _, state := range []int32{2, 4} {
		active := good
		active.State = state
		if got := installationTaskObservation(active, "orphan"); got.Problem != "INSTALL_ORPHAN_TASK_ACTIVE_OR_CHANGED" {
			t.Fatalf("active orphan accepted: %+v", got)
		}
	}
}

func TestLegacyIntegrationTargetCannotAdoptCurrentOrForeignSources(t *testing.T) {
	root, old := `C:\Program Files\USB Link`, `C:\Program Files\Suhang iPad USB`
	for _, p := range []string{root + `\0.8.97\USB-Link.exe`, root + `\0.8.139\USB-Link.exe`, root + `\0.9.3\USB-Link.exe`, old + `\0.8.1\Suhang-iPad-USB.exe`, `c:/program files/usb link/0.8.97/USB-Link.exe`} {
		if !legacyIntegrationTarget(p, root, old) {
			t.Errorf("rejected historical target %s", p)
		}
	}
	for _, p := range []string{root + `\App\USB-Link.exe`, root + `\Candidate\USB-Link.exe`, root + `\Previous\USB-Link.exe`, root + `\..\0.8.97\USB-Link.exe`, root + `\0.8.97\..\USB-Link.exe`, root + `\0.8.97\USB-Link.exe:stream`, root + `\0.8.97\USB-Link.exe `, root + `-Other\0.8.97\USB-Link.exe`, root + `\0.8.97\other.exe`, old + `\0.8.97\USB-Link.exe`, `\\server\USB Link\0.8.97\USB-Link.exe`, `D:\Program Files\USB Link\0.8.97\USB-Link.exe`} {
		if legacyIntegrationTarget(p, root, old) {
			t.Errorf("accepted foreign/current target %s", p)
		}
	}
}

func TestNewSetupRecoveryOnlyFinishesFirstInstallRollback(t *testing.T) {
	_, x := installationFixture(t)
	x.Previous = nil
	x.PreviousFiles = nil
	x.Phase = InstallRestoring
	x.Next.Version = "0.10.10"
	if !canFinishInstallationRollback(x, x.OwnerSID, "0.10.11") {
		t.Fatal("reported restoration blocked")
	}
	for _, p := range []InstallationPhase{InstallStaged, InstallQuiescing, InstallPreviousBound, InstallPublished, InstallStarted, InstallAccepted, InstallCleaning, InstallComplete, InstallRolledBack} {
		changed := x
		changed.Phase = p
		if canFinishInstallationRollback(changed, x.OwnerSID, "0.10.11") {
			t.Fatalf("new setup allowed to resume %s", p)
		}
	}
	for _, version := range []string{"0.10.10", "0.10.9", "bad"} {
		if canFinishInstallationRollback(x, x.OwnerSID, version) {
			t.Fatal(version)
		}
	}
	if canFinishInstallationRollback(x, "S-1-5-21-8-8-8-8", "0.10.11") {
		t.Fatal("foreign owner")
	}
	_, upgrade := installationFixture(t)
	upgrade.Phase = InstallRestoring
	if canFinishInstallationRollback(upgrade, upgrade.OwnerSID, "0.10.11") {
		t.Fatal("upgrade rollback accepted")
	}
	x.NextFiles[BinaryName] = strings.Repeat("f", 64)
	if canFinishInstallationRollback(x, x.OwnerSID, "0.10.11") {
		t.Fatal("corrupt inventory accepted")
	}
}

func TestIntegrationRecoveryBacksUpAllBeforeRemovalAndDetectsChanges(t *testing.T) {
	for _, fault := range []string{"", "check:a:1", "check:b:1", "backup:a", "backup:b", "check:b:2", "check:a:3", "remove:a", "check:b:3", "remove:b"} {
		t.Run(fault, func(t *testing.T) {
			calls := []string{}
			checks := map[string]int{}
			invoke := func(n string) error {
				calls = append(calls, n)
				if n == fault {
					return errors.New(n)
				}
				return nil
			}
			actions := []integrationRecoveryAction{}
			for _, n := range []string{"a", "b"} {
				actions = append(actions, integrationRecoveryAction{
					Backup:  func() error { return invoke("backup:" + n) },
					Recheck: func() error { checks[n]++; return invoke("check:" + n + ":" + string(rune('0'+checks[n]))) },
					Remove:  func() error { return invoke("remove:" + n) },
				})
			}
			e := recoverInstallationIntegrations(actions)
			if (e != nil) != (fault != "") {
				t.Fatalf("fault=%s err=%v", fault, e)
			}
			seen := map[string]bool{}
			for _, c := range calls {
				if strings.HasPrefix(c, "remove:") && (!seen["backup:a"] || !seen["backup:b"] || !seen["check:a:2"] || !seen["check:b:2"]) {
					t.Fatal("removed before ALL backups and rechecks", calls)
				}
				seen[c] = true
			}
			if strings.HasPrefix(fault, "check:") && strings.HasSuffix(fault, ":1") && (!seen["check:a:1"] || !seen["check:b:1"]) {
				t.Fatal("first error hid independent checks", calls)
			}
		})
	}
}

func TestRecoveryUsesOldJournalWithoutPublishingOrStartingOldCandidate(t *testing.T) {
	f, x := installationFixture(t)
	x.Phase = InstallRestoring
	x.Previous = nil
	x.PreviousFiles = nil
	old := x.Next
	inventory := map[string]string{}
	for n, h := range x.NextFiles {
		inventory[n] = h
	}
	got, e := ExecuteInstallation(context.Background(), x, f)
	if e != nil || got.Phase != InstallRolledBack || !f.restored {
		t.Fatal(got.Phase, e)
	}
	if got.Next != old || !reflect.DeepEqual(got.NextFiles, inventory) {
		t.Fatal("rollback changed old authority")
	}
	for _, c := range f.calls {
		if c == "publish" || c == "start" || c == "bind-previous" {
			t.Fatal("rollback ran forward operation", c)
		}
	}
}

func TestIntegrationRecoveryResumesAfterPartialRemoval(t *testing.T) {
	live := map[string]string{"task": "original XML", "shortcut": "original shortcut bytes"}
	backup := map[string]string{}
	fail := true
	run := func() error {
		actions := []integrationRecoveryAction{}
		for _, name := range []string{"task", "shortcut"} {
			content, present := live[name]
			if !present {
				continue
			}
			actions = append(actions, integrationRecoveryAction{
				Backup: func() error {
					if old, ok := backup[name]; ok && old != content {
						return errors.New("backup changed")
					}
					backup[name] = content
					return nil
				},
				Recheck: func() error {
					if live[name] != content {
						return errors.New("object changed")
					}
					return nil
				},
				Remove: func() error {
					if name == "shortcut" && fail {
						return errors.New("injected interruption")
					}
					delete(live, name)
					return nil
				},
			})
		}
		return recoverInstallationIntegrations(actions)
	}
	if run() == nil || len(live) != 1 || len(backup) != 2 {
		t.Fatal("wrong interrupted state", live, backup)
	}
	fail = false
	if e := run(); e != nil || len(live) != 0 || backup["task"] != "original XML" || backup["shortcut"] != "original shortcut bytes" {
		t.Fatal("resume lost backup or failed", live, backup, e)
	}
	if e := run(); e != nil {
		t.Fatal("empty retry", e)
	}
}
