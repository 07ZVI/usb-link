package installcleanup

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func safeFixture(p string) bool {
	st, err := os.Lstat(p)
	return err == nil && st.Mode()&os.ModeSymlink == 0
}
func fixture(t *testing.T) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	inv := map[string]string{}
	for _, name := range []string{"a.dll", "b.exe"} {
		b := []byte(name)
		h := sha256.Sum256(b)
		inv[name] = hex.EncodeToString(h[:])
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "receipt.json"), []byte("protected receipt"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir, inv
}
func TestInterruptedRemovalRemainsRetryable(t *testing.T) {
	dir, inv := fixture(t)
	files, err := Files(dir, "receipt.json", inv, 1024, safeFixture)
	if err != nil {
		t.Fatal(err)
	}
	err = Remove(dir, files, func(p string) error {
		if filepath.Base(p) == "b.exe" {
			return errors.New("in use")
		}
		return os.Remove(p)
	})
	if err == nil {
		t.Fatal("lock ignored")
	}
	if _, err = os.Stat(filepath.Join(dir, "receipt.json")); err != nil {
		t.Fatal("receipt deleted before executable")
	}
	files, err = Files(dir, "receipt.json", inv, 1024, safeFixture)
	if err != nil {
		t.Fatal(err)
	}
	if err = Remove(dir, files, os.Remove); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("retired directory remains", err)
	}
}
func TestUnknownChangedAndRedirectedFilesPreventDeletion(t *testing.T) {
	for _, kind := range []string{"extra", "changed", "redirect", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir, inv := fixture(t)
			p := filepath.Join(dir, "a.dll")
			switch kind {
			case "extra":
				os.WriteFile(filepath.Join(dir, "user.txt"), []byte("data"), 0600)
			case "changed":
				os.WriteFile(p, []byte("modified"), 0600)
			case "redirect":
				os.Remove(p)
				os.Symlink(filepath.Join(dir, "b.exe"), p)
			case "directory":
				os.Remove(p)
				os.Mkdir(p, 0700)
			}
			files, err := Files(dir, "receipt.json", inv, 1024, safeFixture)
			if err == nil || len(files) != 0 {
				t.Fatal("unsafe plan accepted")
			}
			if _, err = os.Stat(filepath.Join(dir, "b.exe")); err != nil {
				t.Fatal("validation deleted other contents")
			}
		})
	}
}
func TestUpdateAndVersionRetention(t *testing.T) {
	for _, state := range []string{"staged", "awaiting_local_approval", "awaiting_auto_install", "handoff", "starting", "manual_recovery_required", "", "future_state"} {
		if UpdateTerminal(state) {
			t.Fatal("rollback dependency deletable", state)
		}
	}
	for _, state := range []string{"complete", "failed", "rollback", "declined"} {
		if !UpdateTerminal(state) {
			t.Fatal(state)
		}
	}
	for _, pair := range [][2]string{{"0.8.9", "0.8.46"}, {"0.7.50", "0.8.1"}, {"0.8.46", "0.8.48"}} {
		if !OlderVersion(pair[0], pair[1]) {
			t.Fatal(pair)
		}
	}
	for _, pair := range [][2]string{{"0.8.46", "0.8.46"}, {"0.8.47", "0.8.46"}, {"invalid", "0.8.46"}, {"0.8.46", "bad"}} {
		if OlderVersion(pair[0], pair[1]) {
			t.Fatal(pair)
		}
	}
}
func TestInventoryRejectsTraversalAndInvalidHashes(t *testing.T) {
	for _, name := range []string{".", "..", "../outside", "C:stream", "a\\b", "receipt.json"} {
		dir, inv := fixture(t)
		inv[name] = inv["a.dll"]
		if _, err := Files(dir, "receipt.json", inv, 1024, safeFixture); err == nil {
			t.Fatal(name)
		}
	}
	dir, inv := fixture(t)
	inv["a.dll"] = "not-a-hash"
	if _, err := Files(dir, "receipt.json", inv, 1024, safeFixture); err == nil {
		t.Fatal("invalid digest")
	}
}
