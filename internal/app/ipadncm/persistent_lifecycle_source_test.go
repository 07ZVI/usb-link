package ipadncm

import (
	"os"
	"strings"
	"testing"
)

// These source contracts complement the portable phase/identity fault matrix:
// they check the actual Windows producer/recovery path, not a fixture-only flow.
func TestIPadActualProducerPersistsIntentBeforeEverySystemWrite(t *testing.T) {
	b, e := os.ReadFile("application_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	start := strings.Index(s, "func (b *groupingBackend) runApplication(")
	s = s[start:]
	first := strings.Index(s, "b.prepareIPadConfiguration(")
	for _, write := range []string{"saveApplicationJournal(b.dir, j, false)", "setUSBHostFlags(plan, false)", "configuration.beforeAddress(ctx)", "createApplicationAddress(plan)"} {
		if strings.Index(s, write) <= first {
			t.Fatalf("%s preceded protected intent", write)
		}
	}
	saved := strings.Index(s, "plan.CreatedAt = stamp")
	captured := strings.Index(s, "configuration.afterAddress(ctx, plan)")
	if saved < 0 || captured <= saved || !strings.Contains(s[saved:captured], "saveApplicationJournal(b.dir, j, true)") {
		t.Fatal("Store mutation lost early active creation checkpoint")
	}
	b, e = os.ReadFile("persistent_application_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(b), "CaptureIPadPersistentIntent(ctx") || !strings.Contains(string(b), "CheckpointIPadPersistentReady(ctx") {
		t.Fatal("pending and fully verified ready boundaries missing")
	}
}
func TestIPadRestoreRemainsAvailableWithFlagsOffAndBeforeGrouping(t *testing.T) {
	b, e := os.ReadFile("persistent_uninstall_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, forbidden := range []string{"PersistentEnabled()", "DADZeroEnabled()", "CreateUnicast", "RecoverGrouping(", "RestorePersistentNetworkGrouping(", "Inspect("} {
		if strings.Contains(s, forbidden) {
			t.Fatal("restore falls through product/diagnostic path", forbidden)
		}
	}
	previous := -1
	for _, phase := range []string{"RequestIPadPersistentRestore(dir)", "BeginIPadPersistentRestore(ctx", "RestoreDADZero(ctx", "RestorePersistent(ctx", "removeApplicationAddress(v.Plan)", "FinishIPadPersistentBinding(ctx"} {
		i := strings.Index(s, phase)
		if i <= previous {
			t.Fatal("restore ordering missing", phase)
		}
		previous = i
	}
	b, e = os.ReadFile("application_recovery_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s = string(b)
	if strings.Index(s, "recoverIPadConfigurationBeforeAddress(") > strings.Index(s, "ipErr = removeApplicationAddress(j.Plan)") {
		t.Fatal("address deleted before original/binding verification")
	}
}
