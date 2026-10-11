package connectioninstall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testInstallationFiles(t *testing.T) installationFiles {
	t.Helper()
	return installationFiles{
		protect: func(path string, directory bool) error {
			s, e := os.Lstat(path)
			if e != nil {
				return e
			}
			if s.Mode()&os.ModeSymlink != 0 || s.IsDir() != directory || !directory && !s.Mode().IsRegular() {
				return fmt.Errorf("unsafe test path")
			}
			return nil
		},
		publish: func(from, to string) error {
			// No replacement, just like production MOVEFILE_WRITE_THROUGH without
			// REPLACE_EXISTING. Link/remove is atomic on this disposable test volume.
			if e := os.Link(from, to); e != nil {
				return e
			}
			return os.Remove(from)
		},
	}
}
func testFileSum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func testRelease(t *testing.T, fs installationFiles) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	if e := os.Mkdir(filepath.Join(dir, "Desktop"), 0700); e != nil {
		t.Fatal(e)
	}
	for name, data := range map[string]string{BinaryName: "previous executable", "ownership.json": "previous receipt", "Desktop/USBLink.Desktop.exe": "previous UI", "Desktop/desktop-ownership.json": "publisher inventory"} {
		if e := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
	}
	inv, e := fs.inventory(dir)
	if e != nil {
		t.Fatal(e)
	}
	return dir, inv
}
func TestInstallationFilesResumeInterruptedCloneAndDelete(t *testing.T) {
	fs := testInstallationFiles(t)
	from, inv := testRelease(t, fs)
	to := filepath.Join(t.TempDir(), "App")
	if e := os.Mkdir(to, 0700); e != nil {
		t.Fatal(e)
	}
	source, _ := os.ReadFile(filepath.Join(from, BinaryName))
	if e := os.WriteFile(filepath.Join(to, BinaryName)+".part", source[:7], 0600); e != nil {
		t.Fatal(e)
	}
	if e := fs.clone(from, to, inv); e != nil {
		t.Fatal(e)
	}
	if e := fs.verify(to, inv, false); e != nil {
		t.Fatal(e)
	}
	// An interrupted cleanup may have removed some files already.
	if e := os.Remove(filepath.Join(to, "Desktop", "USBLink.Desktop.exe")); e != nil {
		t.Fatal(e)
	}
	if e := fs.remove(to, inv); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Lstat(to); !os.IsNotExist(e) {
		t.Fatalf("release directory remains: %v", e)
	}
	if e := fs.remove(to, inv); e != nil {
		t.Fatalf("cleanup is not resumable: %v", e)
	}
}
func TestInstallationFilesPreserveChangedPartialAndForeignContents(t *testing.T) {
	for _, kind := range []string{"changed-part", "foreign-file", "foreign-dir", "changed-owned-file"} {
		t.Run(kind, func(t *testing.T) {
			fs := testInstallationFiles(t)
			from, inv := testRelease(t, fs)
			to := filepath.Join(t.TempDir(), "App")
			if e := fs.clone(from, to, inv); e != nil {
				t.Fatal(e)
			}
			var foreign string
			switch kind {
			case "changed-part":
				foreign = filepath.Join(to, BinaryName) + ".part"
				os.WriteFile(foreign, []byte("unrelated bytes"), 0600)
			case "foreign-file":
				foreign = filepath.Join(to, "personal.txt")
				os.WriteFile(foreign, []byte("user file"), 0600)
			case "foreign-dir":
				foreign = filepath.Join(to, "Work")
				os.Mkdir(foreign, 0700)
			case "changed-owned-file":
				foreign = filepath.Join(to, BinaryName)
				os.WriteFile(foreign, []byte("changed image"), 0600)
			}
			if e := fs.clone(from, to, inv); e == nil {
				t.Fatal("unexpected content accepted")
			}
			if _, e := os.Lstat(foreign); e != nil {
				t.Fatalf("foreign content touched: %v", e)
			}
			if e := fs.remove(to, inv); e == nil {
				t.Fatal("unknown contents deleted")
			}
			if _, e := os.Lstat(foreign); e != nil {
				t.Fatalf("foreign content deleted: %v", e)
			}
		})
	}
}
func TestInstallationFilesNeverReplaceRacingTarget(t *testing.T) {
	fs := testInstallationFiles(t)
	dir := t.TempDir()
	target := filepath.Join(dir, BinaryName)
	original := []byte("publisher core")
	other := []byte("another installer")
	publish := fs.publish
	fs.publish = func(a, b string) error {
		if e := os.WriteFile(b, other, 0600); e != nil {
			return e
		}
		return publish(a, b)
	}
	e := fs.write(target, testFileSum(original), func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(string(original))), nil })
	if e == nil {
		t.Fatal("racing target overwritten")
	}
	got, _ := os.ReadFile(target)
	if string(got) != string(other) {
		t.Fatal("foreign target changed")
	}
}
func TestInstallationFilesRejectRedirectedRuntimeBeforeRemoval(t *testing.T) {
	fs := testInstallationFiles(t)
	dir, inv := testRelease(t, fs)
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("preserve"), 0600)
	target := filepath.Join(dir, "Desktop", "USBLink.Desktop.exe")
	os.Remove(target)
	if e := os.Symlink(outside, target); e != nil {
		t.Skipf("symlink unavailable: %v", e)
	}
	if e := fs.remove(dir, inv); e == nil {
		t.Fatal("symlink accepted")
	}
	got, _ := os.ReadFile(outside)
	if string(got) != "preserve" {
		t.Fatal("outside file modified")
	}
	if _, e := os.Stat(filepath.Join(dir, BinaryName)); e != nil {
		t.Fatal("verification did not precede deletion")
	}
}
func TestInstallationFilesFailedPublicationRetainsVerifiedCopy(t *testing.T) {
	fs := testInstallationFiles(t)
	fs.publish = func(string, string) error { return errors.New("file in use") }
	target := filepath.Join(t.TempDir(), BinaryName)
	data := []byte("new publisher executable")
	e := fs.write(target, testFileSum(data), func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(string(data))), nil })
	if e == nil {
		t.Fatal("occupancy ignored")
	}
	got, _ := os.ReadFile(target + ".part")
	if string(got) != string(data) {
		t.Fatal("candidate bytes lost")
	}
	fs.publish = testInstallationFiles(t).publish
	if e := fs.write(target, testFileSum(data), func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(string(data))), nil }); e != nil {
		t.Fatal(e)
	}
	got, _ = os.ReadFile(target)
	if string(got) != string(data) {
		t.Fatal("retry did not publish same bytes")
	}
}
