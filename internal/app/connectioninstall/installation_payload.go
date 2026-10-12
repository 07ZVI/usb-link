package connectioninstall

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

func plannedInstallationInventory(next Receipt, archive io.ReaderAt, size int64) (map[string]string, error) {
	z, e := zip.NewReader(archive, size)
	if e != nil {
		return nil, e
	}
	index, present, e := embeddedDesktopIndex(z)
	if e != nil {
		return nil, fmt.Errorf("INSTALL_PUBLISHER_DESKTOP_INDEX_INVALID: %w", e)
	}
	if !present {
		return nil, fmt.Errorf("INSTALL_PUBLISHER_DESKTOP_INDEX_REQUIRED: desktop-ownership.json missing")
	}
	receipt, _ := json.Marshal(next)
	h := sha256.Sum256(receipt)
	inv := map[string]string{BinaryName: next.SHA, "ownership.json": hex.EncodeToString(h[:])}
	for name, h := range index {
		inv["Desktop/"+name] = hex.EncodeToString(h[:])
	}
	return inv, nil
}
func stageInstallationPayload(fs installationFiles, candidate string, t InstallationTransaction, self string, archive io.ReaderAt, size int64, sourceSafe func(string) error) error {
	want, e := plannedInstallationInventory(t.Next, archive, size)
	if e != nil || !reflect.DeepEqual(want, t.NextFiles) {
		return fmt.Errorf("INSTALL_STAGED_PAYLOAD_CHANGED")
	}
	if e = fs.mkdir(candidate); e != nil {
		return e
	}
	if e = fs.write(filepath.Join(candidate, BinaryName), t.Next.SHA, func() (io.ReadCloser, error) {
		if e := sourceSafe(self); e != nil {
			return nil, e
		}
		return os.Open(self)
	}); e != nil {
		return e
	}
	receipt, _ := json.Marshal(t.Next)
	if e = fs.write(filepath.Join(candidate, "ownership.json"), t.NextFiles["ownership.json"], func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(receipt)), nil }); e != nil {
		return e
	}
	dir := filepath.Join(candidate, "Desktop")
	if e = fs.mkdir(dir); e != nil {
		return e
	}
	z, e := zip.NewReader(archive, size)
	if e != nil {
		return e
	}
	for _, entry := range z.File {
		if e = fs.write(filepath.Join(dir, entry.Name), t.NextFiles["Desktop/"+entry.Name], entry.Open); e != nil {
			return e
		}
	}
	return fs.verify(candidate, t.NextFiles, false)
}

// ValidateInstallationPayload verifies every immutable byte before component
// preparation, legacy removal or creating installation directories. It is also
// required by the build against the actual archive that is embedded in setup.
func ValidateInstallationPayload(version string, archive io.ReaderAt, size int64) error {
	if archive == nil || size <= 0 {
		return fmt.Errorf("INSTALL_PAYLOAD_MISSING")
	}
	next := Receipt{ProductID, version, strings.Repeat("0", 64)}
	inv, err := plannedInstallationInventory(next, archive, size)
	if err != nil {
		return err
	}
	t := InstallationTransaction{Schema: 1, Product: ProductID, OwnerSID: "S-1-5-21-4294967295-4294967295-4294967295-4294967295", Phase: InstallStaged, Next: next, NextFiles: inv}
	if err := validateInstallationTransaction(t); err != nil {
		return err
	}
	z, err := zip.NewReader(archive, size)
	if err != nil {
		return err
	}
	var problems []error
	for _, name := range []string{"USBLink.Desktop.exe", "USBLink.Desktop.dll", "USBLink.Desktop.deps.json", "USBLink.Desktop.runtimeconfig.json"} {
		if inv["Desktop/"+name] == "" {
			problems = append(problems, fmt.Errorf("INSTALL_DESKTOP_FILE_MISSING: %s", name))
		}
	}
	for _, entry := range z.File {
		r, err := entry.Open()
		if err != nil {
			problems = append(problems, fmt.Errorf("INSTALL_PAYLOAD_ENTRY: %s: %w", entry.Name, err))
			continue
		}
		h := sha256.New()
		n, readErr := io.Copy(h, io.LimitReader(r, desktopEntryLimit+1))
		closeErr := r.Close()
		if readErr != nil || closeErr != nil || uint64(n) != entry.UncompressedSize64 || hex.EncodeToString(h.Sum(nil)) != inv["Desktop/"+entry.Name] {
			problems = append(problems, fmt.Errorf("INSTALL_PAYLOAD_HASH_MISMATCH: %s (read=%v, close=%v)", entry.Name, readErr, closeErr))
		}
	}
	return errors.Join(problems...)
}
