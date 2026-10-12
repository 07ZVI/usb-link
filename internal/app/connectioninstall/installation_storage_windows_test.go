//go:build windows && amd64

package connectioninstall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// Exercises actual Windows ACL inheritance, no-replace publication, protected
// journal readback and cleanup in a temporary tree; never touches product SCM,
// registry, Program Files, installed data or network settings.
func TestNativeInstallationStorageContract(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires elevated Windows test runner for administrator-owned ACLs")
	}
	root, err := protectedRootAt(filepath.Join(t.TempDir(), "storage"), true)
	if err != nil {
		t.Fatal(err)
	}
	self := filepath.Join(root, "source.exe")
	content := bytes.Repeat([]byte("publisher source"), 256)
	if err := os.WriteFile(self, content, 0600); err != nil {
		t.Fatal(err)
	}
	archive := indexedDesktopZip(t, installationDesktopFixture(), nil)
	next := Receipt{ProductID, "0.10.10", testFileSum(content)}
	inv, err := plannedInstallationInventory(next, bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	transaction := InstallationTransaction{Schema: 1, Product: ProductID, OwnerSID: user.User.Sid.String(), Phase: InstallStaged, Next: next, NextFiles: inv}
	candidate := filepath.Join(root, "Candidate")
	app := filepath.Join(root, "App")
	journal := filepath.Join(root, "transaction.json")
	if err := writeInstallationJSON(journal, transaction); err != nil {
		t.Fatal(err)
	}
	raw, err := coreProtectedReadBounded(journal, false, true, 32768)
	if err != nil {
		t.Fatal(err)
	}
	var observed InstallationTransaction
	if json.Unmarshal(raw, &observed) != nil || observed.Next != next {
		t.Fatal("journal identity did not round trip")
	}
	for i := 0; i < 2; i++ {
		if err := stageInstallationPayload(installationReleaseFiles, candidate, transaction, self, bytes.NewReader(archive), int64(len(archive)), noReparse); err != nil {
			t.Fatalf("stage/resume: %v", err)
		}
	}
	if err := copyReleaseFiles(candidate, app, inv); err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseFiles(app, inv, false); err != nil {
		t.Fatal(err)
	}
	transaction.Phase = InstallComplete
	if err := writeInstallationJSON(journal, transaction); err != nil {
		t.Fatal(err)
	}
	if err := removeReleaseFiles(candidate, inv); err != nil {
		t.Fatal(err)
	}
	if err := removeReleaseFiles(app, inv); err != nil {
		t.Fatal(err)
	}
}
