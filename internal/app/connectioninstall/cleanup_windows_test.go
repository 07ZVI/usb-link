//go:build windows && amd64

package connectioninstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDesktopDeletionInventoryRetainsReceiptUntilLast(t *testing.T) {
	dir := t.TempDir()
	b := []byte("owned DLL")
	h := sha256.Sum256(b)
	r := struct {
		Product string            `json:"product"`
		Files   map[string]string `json:"files"`
	}{ProductID, map[string]string{"owned.dll": hex.EncodeToString(h[:])}}
	marker, _ := json.Marshal(r)
	os.WriteFile(filepath.Join(dir, "desktop-ownership.json"), marker, 0600)
	os.WriteFile(filepath.Join(dir, "owned.dll"), b, 0600)
	files, err := desktopRemovalFiles(dir)
	if err != nil || len(files) != 2 || filepath.Base(files[1]) != "desktop-ownership.json" {
		t.Fatal(files, err)
	}
	os.Remove(filepath.Join(dir, "owned.dll"))
	files, err = desktopRemovalFiles(dir)
	if err != nil || len(files) != 1 {
		t.Fatal("interrupted removal cannot resume", files, err)
	}
	os.WriteFile(filepath.Join(dir, "user-data.txt"), []byte("retain"), 0600)
	if _, err = desktopRemovalFiles(dir); err == nil {
		t.Fatal("unknown file accepted")
	}
}

func TestCleanupNeverWaitsForAnIncomingRelease(t *testing.T) {
	installationCleanupMu.Lock()
	defer installationCleanupMu.Unlock()
	r := cleanupInstallation("0.8.46", "desktop-012345678901234567890123", nil)
	if !r.Pending || len(r.Preserved) != 1 {
		t.Fatal(r)
	}
}

func TestCancelledCleanupCanBeJoined(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	finish := StartInstallationCleanup(ctx, "0.8.46", "desktop-012345678901234567890123", nil)
	finish()
}

func TestReadableDesktopReleaseRejectsChangedAndUnknownFiles(t *testing.T) {
	root := t.TempDir()
	payload := desktopTestZip(t, "USBLink.Desktop.exe", "runtime.dll")
	reader := bytes.NewReader(payload)
	target, err := prepareDesktopAt(reader, int64(len(payload)), root, "0.9.3")
	if err != nil || target != filepath.Join(root, "0.9.3", "USBLink.Desktop.exe") {
		t.Fatal(target, err)
	}
	if _, err = prepareDesktopAt(reader, int64(len(payload)), root, "0.9.3"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "0.9.3", "extra.dll"), []byte("unknown"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = prepareDesktopAt(reader, int64(len(payload)), root, "0.9.3"); err == nil {
		t.Fatal("unknown DLL admitted")
	}
	os.Remove(filepath.Join(root, "0.9.3", "extra.dll"))
	os.WriteFile(filepath.Join(root, "0.9.3", "runtime.dll"), []byte("changed"), 0600)
	if _, err = prepareDesktopAt(reader, int64(len(payload)), root, "0.9.3"); err == nil {
		t.Fatal("changed runtime admitted")
	}
}
