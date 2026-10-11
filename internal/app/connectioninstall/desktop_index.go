package connectioninstall

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const desktopOwnershipName = "desktop-ownership.json"
const desktopOwnershipLimit = 64 << 10

// Only the manifest inside the immutable publisher-verified archive supplies
// expected hashes. The installed manifest is just another independently hashed
// file; it can never authorize reuse of a changed runtime or extra DLL.
func embeddedDesktopIndex(z *zip.Reader) (map[string][32]byte, bool, error) {
	var manifest *zip.File
	names := make(map[string]bool)
	var total uint64
	for _, f := range z.File {
		name := f.Name
		if name == "" || name == "." || name == ".." || name != filepath.Base(name) || strings.ContainsAny(name, "\\:/") || !f.Mode().IsRegular() || f.UncompressedSize64 > desktopEntryLimit || names[strings.ToLower(name)] {
			return nil, false, fmt.Errorf("invalid desktop payload entry")
		}
		names[strings.ToLower(name)] = true
		total += f.UncompressedSize64
		if total > 300<<20 || len(names) > 1024 {
			return nil, false, fmt.Errorf("desktop payload too large")
		}
		if name == desktopOwnershipName {
			manifest = f
		}
	}
	if !names["usblink.desktop.exe"] {
		return nil, false, fmt.Errorf("desktop executable missing")
	}
	if manifest == nil {
		return nil, false, nil
	} // Historical archives retain full verification.
	if manifest.UncompressedSize64 > desktopOwnershipLimit {
		return nil, true, fmt.Errorf("desktop manifest too large")
	}
	r, err := manifest.Open()
	if err != nil {
		return nil, true, err
	}
	b, err := io.ReadAll(io.LimitReader(r, desktopOwnershipLimit+1))
	r.Close()
	if err != nil || uint64(len(b)) != manifest.UncompressedSize64 {
		return nil, true, fmt.Errorf("desktop manifest damaged")
	}
	index, err := parseDesktopIndex(b)
	if err != nil {
		return nil, true, err
	}
	if len(index) != len(z.File)-1 {
		return nil, true, fmt.Errorf("desktop manifest inventory mismatch")
	}
	for _, f := range z.File {
		if f.Name == desktopOwnershipName {
			continue
		}
		if _, ok := index[f.Name]; !ok {
			return nil, true, fmt.Errorf("desktop manifest inventory mismatch")
		}
	}
	index[desktopOwnershipName] = sha256.Sum256(b)
	return index, true, nil
}

func parseDesktopIndex(b []byte) (map[string][32]byte, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("desktop manifest invalid")
	}
	seen := make(map[string]bool)
	index := make(map[string][32]byte)
	for d.More() {
		field, err := d.Token()
		key, ok := field.(string)
		if err != nil || !ok || seen[key] {
			return nil, fmt.Errorf("desktop manifest invalid")
		}
		seen[key] = true
		switch key {
		case "product":
			var product string
			if d.Decode(&product) != nil || product != ProductID {
				return nil, fmt.Errorf("desktop manifest product mismatch")
			}
		case "files":
			token, err := d.Token()
			if err != nil || token != json.Delim('{') {
				return nil, fmt.Errorf("desktop manifest inventory invalid")
			}
			folded := make(map[string]bool)
			for d.More() {
				nameToken, err := d.Token()
				name, ok := nameToken.(string)
				if err != nil || !ok || name == "" || name == "." || name == ".." || name != filepath.Base(name) || strings.ContainsAny(name, "\\:/") || name == desktopOwnershipName || folded[strings.ToLower(name)] || len(index) >= 1024 {
					return nil, fmt.Errorf("desktop manifest inventory invalid")
				}
				folded[strings.ToLower(name)] = true
				var hash string
				if d.Decode(&hash) != nil || len(hash) != 64 || hash != strings.ToLower(hash) {
					return nil, fmt.Errorf("desktop manifest hash invalid")
				}
				raw, err := hex.DecodeString(hash)
				if err != nil || len(raw) != 32 {
					return nil, fmt.Errorf("desktop manifest hash invalid")
				}
				index[name] = [32]byte(raw)
			}
			token, err = d.Token()
			if err != nil || token != json.Delim('}') {
				return nil, fmt.Errorf("desktop manifest inventory invalid")
			}
		default:
			return nil, fmt.Errorf("desktop manifest field invalid")
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || !seen["product"] || !seen["files"] || d.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("desktop manifest invalid")
	}
	return index, nil
}

func prepareIndexedDesktopEntries(z *zip.Reader, dir string, fresh bool, safePath func(string) error) error {
	index, present, err := embeddedDesktopIndex(z)
	if err != nil {
		return err
	}
	if !present {
		return prepareDesktopEntries(z, dir, fresh, safePath)
	}
	if fresh {
		// New directories still decompress every entry, validate CRC, and perform
		// independent readback before publication, exactly as before.
		if err := prepareDesktopEntries(z, dir, true, safePath); err != nil {
			return err
		}
	}
	buf := make([]byte, 32<<10)
	for _, entry := range z.File {
		path := filepath.Join(dir, entry.Name)
		if err := safePath(path); err != nil {
			return fmt.Errorf("desktop file redirected: %w", err)
		}
		actual, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("desktop file verification failed")
		}
		info, err := actual.Stat()
		if err != nil || !info.Mode().IsRegular() || uint64(info.Size()) != entry.UncompressedSize64 {
			actual.Close()
			return fmt.Errorf("desktop file verification failed")
		}
		got := sha256.New()
		n, readErr := io.CopyBuffer(got, io.LimitReader(actual, desktopEntryLimit+1), buf)
		closeErr := actual.Close()
		expected := index[entry.Name]
		if readErr != nil || closeErr != nil || uint64(n) != entry.UncompressedSize64 || !bytes.Equal(got.Sum(nil), expected[:]) {
			return fmt.Errorf("desktop file verification failed")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != len(index) {
		return fmt.Errorf("desktop directory does not match payload")
	}
	return nil
}
