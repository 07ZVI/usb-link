package connectioninstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type lifecycleFixture struct {
	root     string
	fail     string
	foreign  bool
	accepted bool
	restored bool
	quiesced bool
	bound    string
	calls    []string
	saved    InstallationTransaction
}

func (f *lifecycleFixture) call(name string) error {
	f.calls = append(f.calls, name)
	if name == f.fail {
		return fmt.Errorf("fixture %s failure", name)
	}
	return nil
}
func (f *lifecycleFixture) Save(t InstallationTransaction) error {
	if e := f.call("save:" + string(t.Phase)); e != nil {
		return e
	}
	f.saved = t
	return nil
}
func (f *lifecycleFixture) Verify(t InstallationTransaction) error {
	if f.foreign {
		return errors.New("foreign service identity")
	}
	return f.call("verify")
}
func (f *lifecycleFixture) Quiesce(context.Context, InstallationTransaction) error {
	if e := f.call("quiesce"); e != nil {
		return e
	}
	f.quiesced = true
	return nil
}
func (f *lifecycleFixture) BindPrevious(InstallationTransaction) error {
	if e := f.call("bind-previous"); e != nil {
		return e
	}
	old, e := os.ReadFile(filepath.Join(f.root, "App", BinaryName))
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Join(f.root, "Update", "Previous"), 0700); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(f.root, "Update", "Previous", BinaryName), old, 0600); e != nil {
		return e
	}
	f.bound = "previous"
	return nil
}
func (f *lifecycleFixture) Publish(InstallationTransaction) error {
	if e := f.call("publish"); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(f.root, "App", BinaryName), []byte("new core"), 0600)
}
func (f *lifecycleFixture) Start(InstallationTransaction) error {
	if e := f.call("start"); e != nil {
		return e
	}
	f.bound = "new"
	return nil
}
func (f *lifecycleFixture) AwaitAcceptance(context.Context, InstallationTransaction) error {
	if e := f.call("accept"); e != nil {
		return e
	}
	f.accepted = true
	return nil
}
func (f *lifecycleFixture) Cleanup(InstallationTransaction) error {
	if e := f.call("cleanup"); e != nil {
		return e
	}
	if !f.accepted {
		return errors.New("cleanup before acceptance")
	}
	return os.RemoveAll(filepath.Join(f.root, "Update"))
}
func (f *lifecycleFixture) Restore(InstallationTransaction) error {
	if f.foreign {
		return errors.New("foreign replacement preserved")
	}
	if e := f.call("restore"); e != nil {
		return e
	}
	path := filepath.Join(f.root, "Update", "Previous", BinaryName)
	if b, e := os.ReadFile(path); e == nil {
		if e = os.WriteFile(filepath.Join(f.root, "App", BinaryName), b, 0600); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	f.bound = "old"
	f.restored = true
	return nil
}

func installationFixture(t *testing.T) (*lifecycleFixture, InstallationTransaction) {
	t.Helper()
	f := &lifecycleFixture{root: t.TempDir(), bound: "old"}
	if e := os.Mkdir(filepath.Join(f.root, "App"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(f.root, "App", BinaryName), []byte("old core"), 0600); e != nil {
		t.Fatal(e)
	}
	sid := "S-1-5-21-1-2-3-1001"
	old := strings.Repeat("a", 64)
	next := strings.Repeat("b", 64)
	receipt := strings.Repeat("c", 64)
	x := InstallationTransaction{Schema: 1, Product: ProductID, OwnerSID: sid, Phase: InstallStaged, Next: Receipt{ProductID, "0.10.1", next}, Previous: &CoreServiceBinding{1, ProductID, sid, `C:\Program Files\USB Link\App\USB-Link.exe`, old}, NextFiles: map[string]string{BinaryName: next, "ownership.json": receipt}, PreviousFiles: map[string]string{BinaryName: old, "ownership.json": receipt}}
	return f, x
}

func TestInstallationFailuresRestorePreviousExecutable(t *testing.T) {
	for _, point := range []string{"quiesce", "bind-previous", "publish", "save:published", "start", "save:started", "accept"} {
		t.Run(point, func(t *testing.T) {
			f, x := installationFixture(t)
			f.fail = point
			got, e := ExecuteInstallation(context.Background(), x, f)
			if e == nil || !f.restored || f.bound != "old" || got.Phase != InstallRolledBack || f.saved.Phase != InstallRolledBack {
				t.Fatalf("%v %#v restored=%v bound=%s saved=%s", e, got, f.restored, f.bound, f.saved.Phase)
			}
			b, _ := os.ReadFile(filepath.Join(f.root, "App", BinaryName))
			if string(b) != "old core" {
				t.Fatalf("old image not restored: %q", b)
			}
			for _, c := range f.calls {
				if c == "cleanup" {
					t.Fatal("previous image cleaned on failed update")
				}
			}
		})
	}
}
func TestInstallationSuccessLeavesOneCurrentImage(t *testing.T) {
	f, x := installationFixture(t)
	got, e := ExecuteInstallation(context.Background(), x, f)
	if e != nil || got.Phase != InstallComplete || f.saved.Phase != InstallComplete || f.bound != "new" || !f.accepted || f.restored {
		t.Fatalf("%v %#v fixture=%#v", e, got, f)
	}
	if _, e = os.Stat(filepath.Join(f.root, "Update")); !os.IsNotExist(e) {
		t.Fatalf("temporary previous image remained: %v", e)
	}
	b, _ := os.ReadFile(filepath.Join(f.root, "App", BinaryName))
	if string(b) != "new core" {
		t.Fatalf("%q", b)
	}
}
func TestAcceptedCleanupFailureResumesWithoutRollback(t *testing.T) {
	f, x := installationFixture(t)
	f.fail = "cleanup"
	got, e := ExecuteInstallation(context.Background(), x, f)
	if e == nil || got.Phase != InstallCleaning || f.restored || !f.accepted || f.bound != "new" {
		t.Fatalf("%v %#v %#v", e, got, f)
	}
	f.fail = ""
	f.calls = nil
	got, e = ExecuteInstallation(context.Background(), got, f)
	if e != nil || got.Phase != InstallComplete || f.restored {
		t.Fatalf("%v %#v", e, got)
	}
	for _, c := range f.calls {
		if c == "start" || c == "quiesce" || c == "publish" || c == "restore" {
			t.Fatalf("cleanup repeated live update operation: %s", c)
		}
	}
}
func TestInstallationIdentityChangeNeverRestoresForeignService(t *testing.T) {
	f, x := installationFixture(t)
	f.foreign = true
	_, e := ExecuteInstallation(context.Background(), x, f)
	if e == nil || f.quiesced || f.restored || len(f.calls) != 0 {
		t.Fatalf("foreign identity modified: %v %#v", e, f)
	}
}
func TestInstallationInvalidInventoryHasNoSideEffects(t *testing.T) {
	for _, name := range []string{"../shared.txt", "Desktop/../shared.txt", "Desktop/a.dll:stream", "Desktop/a.dll/child", "Desktop/evil\\file", "Desktop/a.dll ", "elsewhere/a.dll"} {
		t.Run(name, func(t *testing.T) {
			f, x := installationFixture(t)
			x.NextFiles[name] = strings.Repeat("d", 64)
			_, e := ExecuteInstallation(context.Background(), x, f)
			if e == nil || len(f.calls) != 0 {
				t.Fatalf("accepted unsafe inventory: %v %#v", e, f)
			}
		})
	}
}
func TestInstallationCancelledBeforeStopRetainsRunningImage(t *testing.T) {
	f, x := installationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := ExecuteInstallation(ctx, x, f)
	if !errors.Is(e, context.Canceled) || f.quiesced || f.restored || len(f.calls) != 0 {
		t.Fatalf("%v %#v", e, f)
	}
}
func TestInstallationFailedRestoreRetainsRecoveryIntent(t *testing.T) {
	f, x := installationFixture(t)
	x.Phase = InstallRestoring
	f.fail = "restore"
	got, e := ExecuteInstallation(context.Background(), x, f)
	if e == nil || got.Phase != InstallRestoring || f.restored {
		t.Fatalf("%v %#v", e, got)
	}
}
