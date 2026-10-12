package connectioninstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func installationDesktopFixture() map[string][]byte {
	return map[string][]byte{"USBLink.Desktop.exe": []byte("exe"), "USBLink.Desktop.dll": []byte("dll"), "USBLink.Desktop.deps.json": []byte("{}"), "USBLink.Desktop.runtimeconfig.json": []byte("{}")}
}

func TestInstallationPayloadRejectsMissingIndexAndAllCorruptEntries(t *testing.T) {
	legacy := desktopTestZip(t, "USBLink.Desktop.exe")
	if err := ValidateInstallationPayload("0.10.10", bytes.NewReader(legacy), int64(len(legacy))); err == nil || !strings.Contains(err.Error(), "INDEX_REQUIRED") {
		t.Fatal(err)
	}
	content := installationDesktopFixture()
	hashes := map[string]string{}
	for name, b := range content {
		hashes[name] = testFileSum(b)
	}
	manifest, _ := json.Marshal(map[string]any{"product": ProductID, "files": hashes})
	content["USBLink.Desktop.exe"] = []byte("tampered exe")
	content["USBLink.Desktop.dll"] = []byte("tampered dll")
	b := indexedDesktopZip(t, content, manifest)
	err := ValidateInstallationPayload("0.10.10", bytes.NewReader(b), int64(len(b)))
	if err == nil || !strings.Contains(err.Error(), "USBLink.Desktop.exe") || !strings.Contains(err.Error(), "USBLink.Desktop.dll") {
		t.Fatalf("must report both damaged files: %v", err)
	}
	for _, name := range []string{"../escape.dll", "bad.dll ", "bad.dll.", "bad.dll:stream"} {
		content := installationDesktopFixture()
		content[name] = []byte("bad")
		b := indexedDesktopZip(t, content, nil)
		if err := ValidateInstallationPayload("0.10.10", bytes.NewReader(b), int64(len(b))); err == nil {
			t.Fatalf("unsafe payload name accepted: %s", name)
		}
	}
}

func TestInstallationShippedPayloadStagePublishAndCleanup(t *testing.T) {
	archive := os.Getenv("SUHANG_DESKTOP_BENCH_ARCHIVE")
	if archive == "" {
		t.Skip("build entry must supply actual publisher archive")
	}
	b, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	version := os.Getenv("USBLINK_TEST_VERSION")
	if version == "" {
		version = "0.10.10"
	}
	if err := ValidateInstallationPayload(version, bytes.NewReader(b), int64(len(b))); err != nil {
		t.Fatal(err)
	}
	self := os.Getenv("USBLINK_TEST_INSTALLER")
	if self == "" {
		self = filepath.Join(t.TempDir(), "setup.exe")
		if err := os.WriteFile(self, bytes.Repeat([]byte("setup"), 300), 0600); err != nil {
			t.Fatal(err)
		}
	} else {
		exe, err := os.ReadFile(self)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(exe, b) {
			t.Fatal("final installer does not embed the validated desktop archive")
		}
	}
	fs := testInstallationFiles(t)
	sum, err := fs.hash(self)
	if err != nil {
		t.Fatal(err)
	}
	// Setup on a USB/download path is not an installed administrator-owned file.
	// Destination protection must never be required for this source.
	protect := fs.protect
	fs.protect = func(path string, directory bool) error {
		if path == self {
			return errors.New("external setup has no installed ACL")
		}
		return protect(path, directory)
	}
	next := Receipt{ProductID, version, sum}
	inv, err := plannedInstallationInventory(next, bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	transaction := InstallationTransaction{Schema: 1, Product: ProductID, OwnerSID: "S-1-5-21-4294967295-4294967295-4294967295-4294967295", Phase: InstallStaged, Next: next, NextFiles: inv}
	// Actual inventory size must fit both a first installation and an upgrade.
	for _, upgrade := range []bool{false, true} {
		record := transaction
		if upgrade {
			record.Previous = &CoreServiceBinding{1, ProductID, record.OwnerSID, `C:\Program Files\USB Link\App\USB-Link.exe`, sum}
			record.PreviousFiles = inv
			record.PreviousStartType = 2
		}
		if err := validateInstallationTransaction(record); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(record)
		var restored InstallationTransaction
		if json.Unmarshal(raw, &restored) != nil || validateInstallationTransaction(restored) != nil {
			t.Fatal("transaction round trip failed")
		}
	}
	root := t.TempDir()
	candidate := filepath.Join(root, "Candidate")
	app := filepath.Join(root, "App")
	for i := 0; i < 2; i++ {
		if err := stageInstallationPayload(fs, candidate, transaction, self, bytes.NewReader(b), int64(len(b)), desktopSafeTestPath); err != nil {
			t.Fatalf("stage/resume %d: %v", i, err)
		}
	}
	if err := fs.clone(candidate, app, inv); err != nil {
		t.Fatal(err)
	}
	if err := fs.verify(app, inv, false); err != nil {
		t.Fatal(err)
	}
	if err := fs.remove(candidate, inv); err != nil {
		t.Fatal(err)
	}
	if err := fs.verify(app, inv, false); err != nil {
		t.Fatal(err)
	}
	if err := fs.remove(app, inv); err != nil {
		t.Fatal(err)
	}
	t.Logf("validated %d release files; staged, resumed, published, verified and cleaned using production file operations", len(inv))
}

func TestInstallationStagingResumesEveryInterruptedFilePublication(t *testing.T) {
	archive := indexedDesktopZip(t, installationDesktopFixture(), nil)
	for failAt := 1; failAt <= 7; failAt++ {
		fs := testInstallationFiles(t)
		self := filepath.Join(t.TempDir(), "setup.exe")
		content := bytes.Repeat([]byte("setup"), 300)
		if err := os.WriteFile(self, content, 0600); err != nil {
			t.Fatal(err)
		}
		next := Receipt{ProductID, "0.10.10", testFileSum(content)}
		inv, err := plannedInstallationInventory(next, bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			t.Fatal(err)
		}
		tx := InstallationTransaction{Next: next, NextFiles: inv}
		candidate := filepath.Join(t.TempDir(), "Candidate")
		publish := fs.publish
		calls := 0
		fs.publish = func(from, to string) error {
			calls++
			if calls == failAt {
				return errors.New("simulated interrupted publication")
			}
			return publish(from, to)
		}
		if err := stageInstallationPayload(fs, candidate, tx, self, bytes.NewReader(archive), int64(len(archive)), desktopSafeTestPath); err == nil {
			t.Fatalf("publication failure %d not observed", failAt)
		}
		fs.publish = publish
		if err := stageInstallationPayload(fs, candidate, tx, self, bytes.NewReader(archive), int64(len(archive)), desktopSafeTestPath); err != nil {
			t.Fatalf("resume at %d: %v", failAt, err)
		}
		if err := fs.verify(candidate, inv, false); err != nil {
			t.Fatal(err)
		}
	}
}
