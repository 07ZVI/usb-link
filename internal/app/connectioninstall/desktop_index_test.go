package connectioninstall

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func indexedDesktopZip(t testing.TB, content map[string][]byte, manifest []byte) []byte {
	t.Helper()
	if manifest == nil {
		files := map[string]string{}
		for name, b := range content {
			files[name] = fmt.Sprintf("%x", sha256.Sum256(b))
		}
		manifest, _ = json.Marshal(struct {
			Product string            `json:"product"`
			Files   map[string]string `json:"files"`
		}{ProductID, files})
	}
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for name, b := range content {
		w, e := writer.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(b); e != nil {
			t.Fatal(e)
		}
	}
	w, e := writer.Create(desktopOwnershipName)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Write(manifest); e != nil {
		t.Fatal(e)
	}
	if e = writer.Close(); e != nil {
		t.Fatal(e)
	}
	return output.Bytes()
}

func TestIndexedDesktopRejectsDiskTamperAndInventoryChanges(t *testing.T) {
	content := map[string][]byte{"USBLink.Desktop.exe": []byte("exe"), "runtime.dll": []byte("original")}
	z := desktopTestReader(t, indexedDesktopZip(t, content, nil))
	for _, change := range []struct {
		name string
		data []byte
	}{
		{"runtime.dll", []byte("modified")}, {"runtime.dll", []byte("short")}, {"extra.dll", []byte("other")}, {desktopOwnershipName, []byte(`{"product":"fake","files":{}}`)},
	} {
		t.Run(change.name+string(change.data), func(t *testing.T) {
			dir := t.TempDir()
			if err := prepareIndexedDesktopEntries(z, dir, true, desktopSafeTestPath); err != nil {
				t.Fatal(err)
			}
			if err := prepareIndexedDesktopEntries(z, dir, false, desktopSafeTestPath); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, change.name), change.data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := prepareIndexedDesktopEntries(z, dir, false, desktopSafeTestPath); err == nil {
				t.Fatal("tampered directory accepted")
			}
		})
	}
	dir := t.TempDir()
	if err := prepareIndexedDesktopEntries(z, dir, true, desktopSafeTestPath); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, "runtime.dll"))
	os.Symlink(filepath.Join(dir, "USBLink.Desktop.exe"), filepath.Join(dir, "runtime.dll"))
	if err := prepareIndexedDesktopEntries(z, dir, false, desktopSafeTestPath); err == nil {
		t.Fatal("redirected file accepted")
	}
}

func TestIndexedDesktopManifestRejectsAmbiguityAndMissingEntries(t *testing.T) {
	content := map[string][]byte{"USBLink.Desktop.exe": []byte("exe")}
	hash := fmt.Sprintf("%x", sha256.Sum256(content["USBLink.Desktop.exe"]))
	for _, manifest := range []string{
		`{"product":"` + ProductID + `","files":{"USBLink.Desktop.exe":"` + hash + `"},"files":{}}`,
		`{"product":"` + ProductID + `","files":{"USBLink.Desktop.exe":"` + hash + `","USBLink.Desktop.exe":"` + hash + `"}}`,
		`{"product":"` + ProductID + `","files":{"USBLink.Desktop.exe":"` + hash + `","usblink.desktop.exe":"` + hash + `"}}`,
		`{"product":"foreign","files":{}}`, `{"product":"` + ProductID + `","files":null}`,
		`{"product":"` + ProductID + `","files":{}}`,
		`{"product":"` + ProductID + `","files":{"USBLink.Desktop.exe":null}}`,
		`{"product":"` + ProductID + `","files":{"USBLink.Desktop.exe":"` + hash + `"},"path":"foreign"}`,
	} {
		z := desktopTestReader(t, indexedDesktopZip(t, content, []byte(manifest)))
		if err := prepareIndexedDesktopEntries(z, t.TempDir(), true, desktopSafeTestPath); err == nil {
			t.Fatalf("invalid manifest accepted: %s", manifest)
		}
	}
	content["runtime.dll"] = []byte("unexpected")
	manifest := []byte(`{"product":"` + ProductID + `","files":{"USBLink.Desktop.exe":"` + hash + `"}}`)
	if err := prepareIndexedDesktopEntries(desktopTestReader(t, indexedDesktopZip(t, content, manifest)), t.TempDir(), true, desktopSafeTestPath); err == nil {
		t.Fatal("missing manifest runtime accepted")
	}
}

func BenchmarkDesktopIndexedShippedArchive(b *testing.B) {
	archive := os.Getenv("SUHANG_DESKTOP_BENCH_ARCHIVE")
	if archive == "" {
		b.Skip("requires exact published archive")
	}
	image, err := os.ReadFile(archive)
	if err != nil {
		b.Fatal(err)
	}
	z := desktopTestReader(b, image)
	dir := b.TempDir()
	if err := prepareIndexedDesktopEntries(z, dir, true, desktopSafeTestPath); err != nil {
		b.Fatal(err)
	}
	for _, mode := range []string{"full_decompress_readback", "embedded_manifest_readback"} {
		b.Run(mode, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				var err error
				if mode == "full_decompress_readback" {
					err = prepareDesktopEntries(z, dir, false, desktopSafeTestPath)
				} else {
					err = prepareIndexedDesktopEntries(z, dir, false, desktopSafeTestPath)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestIndexedDesktopShippedManifestMatchesArchiveBytes(t *testing.T) {
	archive := os.Getenv("SUHANG_DESKTOP_BENCH_ARCHIVE")
	if archive == "" {
		t.Skip("requires exact published archive")
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(f, stat.Size())
	if err != nil {
		t.Fatal(err)
	}
	index, present, err := embeddedDesktopIndex(z)
	if err != nil || !present {
		t.Fatal("trusted embedded index unavailable", err)
	}
	var total uint64
	for _, entry := range z.File {
		r, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.New()
		n, err := io.Copy(hash, r)
		r.Close()
		want := index[entry.Name]
		if err != nil || uint64(n) != entry.UncompressedSize64 || !bytes.Equal(hash.Sum(nil), want[:]) {
			t.Fatalf("embedded file/manifest mismatch: %s: %v", entry.Name, err)
		}
		total += uint64(n)
	}
	t.Logf("entries=%d archive_bytes=%d uncompressed_bytes=%d every embedded content SHA256 matches publisher manifest", len(z.File), stat.Size(), total)
}

func TestIndexedDesktopKeepsLegacyFallbackAndRejectsIncorrectEmbeddedHashes(t *testing.T) {
	z := desktopTestReader(t, desktopTestZip(t, "USBLink.Desktop.exe", "runtime.dll"))
	dir := t.TempDir()
	if err := prepareIndexedDesktopEntries(z, dir, true, desktopSafeTestPath); err != nil {
		t.Fatal(err)
	}
	if err := prepareIndexedDesktopEntries(z, dir, false, desktopSafeTestPath); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "runtime.dll"), []byte("changed"), 0600)
	if err := prepareIndexedDesktopEntries(z, dir, false, desktopSafeTestPath); err == nil {
		t.Fatal("legacy tamper accepted")
	}
	manifest := []byte(`{"product":"` + ProductID + `","files":{"USBLink.Desktop.exe":"` + strings.Repeat("0", 64) + `"}}`)
	bad := desktopTestReader(t, indexedDesktopZip(t, map[string][]byte{"USBLink.Desktop.exe": []byte("actual executable")}, manifest))
	if err := prepareIndexedDesktopEntries(bad, t.TempDir(), true, desktopSafeTestPath); err == nil {
		t.Fatal("fresh archive/manifest content mismatch accepted")
	}
	for _, name := range []string{"", ".", "..", "../USBLink.Desktop.exe", "folder\\file", "file:stream"} {
		b, _ := json.Marshal(struct {
			Product string            `json:"product"`
			Files   map[string]string `json:"files"`
		}{ProductID, map[string]string{name: strings.Repeat("0", 64)}})
		if _, err := parseDesktopIndex(b); err == nil {
			t.Fatal("unsafe manifest name accepted", name)
		}
	}
}
