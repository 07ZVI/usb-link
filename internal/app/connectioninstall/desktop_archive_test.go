package connectioninstall

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
)

func desktopTestZip(t testing.TB, names ...string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	z := zip.NewWriter(&buffer)
	for _, name := range names {
		w, err := z.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte("desktop-content:" + name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func desktopSafeTestPath(path string) error {
	s, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !s.Mode().IsRegular() {
		return fmt.Errorf("not regular")
	}
	return nil
}

func desktopTestReader(t testing.TB, content []byte) *zip.Reader {
	t.Helper()
	z, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func TestStreamingDesktopRetainsIdentityAndIndependentReadback(t *testing.T) {
	data := desktopTestZip(t, "USBLink.Desktop.exe", "runtime.dll")
	name, err := DesktopDirectoryNameArchive(bytes.NewReader(data), int64(len(data)))
	h := sha256.Sum256(data)
	if err != nil || name != fmt.Sprintf("desktop-%x", h[:12]) {
		t.Fatal(name, err)
	}
	z := desktopTestReader(t, data)
	dir := t.TempDir()
	if err = prepareDesktopEntries(z, dir, true, desktopSafeTestPath); err != nil {
		t.Fatal(err)
	}
	if err = prepareDesktopEntries(z, dir, false, desktopSafeTestPath); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		path string
		data []byte
	}{
		{"runtime.dll", []byte("tampered")},
		{"runtime.dll", bytes.Repeat([]byte{'X'}, len("desktop-content:runtime.dll"))},
		{"runtime.dll", []byte("desktop-content:runtime.dll-extra")},
		{"extra.dll", []byte("unknown")},
	} {
		t.Run(change.path+string(change.data), func(t *testing.T) {
			trial := t.TempDir()
			if err := prepareDesktopEntries(z, trial, true, desktopSafeTestPath); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(trial, change.path), change.data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := prepareDesktopEntries(z, trial, false, desktopSafeTestPath); err == nil {
				t.Fatal("altered runtime accepted")
			}
		})
	}
}

func TestStreamingDesktopRejectsDamagedArchiveAndUnownedPath(t *testing.T) {
	data := desktopTestZip(t, "USBLink.Desktop.exe")
	data[bytes.Index(data, []byte("desktop-content"))] ^= 1
	if err := prepareDesktopEntries(desktopTestReader(t, data), t.TempDir(), true, desktopSafeTestPath); err == nil {
		t.Fatal("bad CRC accepted")
	}
	for _, names := range [][]string{
		{"../USBLink.Desktop.exe"}, {"USBLink.Desktop.exe", "RUNTIME.DLL", "runtime.dll"},
		{"USBLink.Desktop.exe", "dir\\file"}, {"USBLink.Desktop.exe", "file:stream"}, {"runtime.dll"},
	} {
		if err := prepareDesktopEntries(desktopTestReader(t, desktopTestZip(t, names...)), t.TempDir(), true, desktopSafeTestPath); err == nil {
			t.Fatalf("invalid entries accepted: %v", names)
		}
	}
	z := desktopTestReader(t, desktopTestZip(t, "USBLink.Desktop.exe"))
	oversized := desktopTestReader(t, desktopTestZip(t, "USBLink.Desktop.exe"))
	oversized.File[0].UncompressedSize64 = desktopEntryLimit + 1
	if err := prepareDesktopEntries(oversized, t.TempDir(), true, desktopSafeTestPath); err == nil {
		t.Fatal("oversized entry accepted")
	}
	dir := t.TempDir()
	if err := prepareDesktopEntries(z, dir, true, func(string) error { return fmt.Errorf("ownership changed") }); err == nil {
		t.Fatal("path guard bypassed")
	}
	if _, err := DesktopDirectoryNameArchive(bytes.NewReader([]byte{1}), 2); err == nil {
		t.Fatal("short immutable input accepted")
	}
}

func TestDesktopStreamingDefaultOff(t *testing.T) {
	for _, v := range []string{"", "0", "true", "1"} {
		t.Setenv("SUHANG_DESKTOP_STREAMING", v)
		if DesktopStreamingEnabled() != (v == "1") {
			t.Fatal(v)
		}
	}
}

// Point this opt-in offline benchmark at the exact immutable shipped archive.
// A extracts once before timing; both branches then verify the same disk files.
func BenchmarkDesktopShippedArchive(b *testing.B) {
	archive := os.Getenv("SUHANG_DESKTOP_BENCH_ARCHIVE")
	if archive == "" {
		b.Skip("requires exact published desktop archive")
	}
	f, err := os.Open(archive)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		b.Fatal(err)
	}
	z, err := zip.NewReader(f, info.Size())
	if err != nil {
		b.Fatal(err)
	}
	dir := b.TempDir()
	if err = prepareDesktopEntries(z, dir, true, desktopSafeTestPath); err != nil {
		b.Fatal(err)
	}
	b.Run("legacy", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			payload, err := os.ReadFile(archive)
			if err != nil {
				b.Fatal(err)
			}
			_ = sha256.Sum256(payload)
			z := desktopTestReader(b, payload)
			for _, entry := range z.File {
				r, err := entry.Open()
				if err != nil {
					b.Fatal(err)
				}
				want, err := io.ReadAll(io.LimitReader(r, desktopEntryLimit+1))
				r.Close()
				if err != nil {
					b.Fatal(err)
				}
				got, err := os.ReadFile(filepath.Join(dir, entry.Name))
				if err != nil || sha256.Sum256(got) != sha256.Sum256(want) {
					b.Fatal("readback mismatch", err)
				}
			}
		}
	})
	b.Run("streaming", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := DesktopDirectoryNameArchive(f, info.Size()); err != nil {
				b.Fatal(err)
			}
			z, err := zip.NewReader(f, info.Size())
			if err != nil {
				b.Fatal(err)
			}
			if err = prepareDesktopEntries(z, dir, false, desktopSafeTestPath); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestDesktopStartupNameAllocationEvidence(t *testing.T) {
	archive := os.Getenv("SUHANG_DESKTOP_BENCH_ARCHIVE")
	if archive == "" {
		t.Skip("requires exact published desktop archive")
	}
	// Preload once to model embed.FS immutable image bytes; those bytes are
	// excluded from both branches' Go heap deltas, as in the Windows installer.
	image, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)
	measure := func(name string, action func() string) string {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		result := action()
		runtime.ReadMemStats(&after)
		t.Logf("%s total_alloc_delta=%d heap_alloc_delta=%d heap_inuse_delta=%d", name,
			after.TotalAlloc-before.TotalAlloc, after.HeapAlloc-before.HeapAlloc, after.HeapInuse-before.HeapInuse)
		return result
	}
	legacy := measure("legacy_startup_name", func() string {
		// embed.FS.ReadFile allocates the same-sized copy before hashing.
		payload := bytes.Clone(image)
		h := sha256.Sum256(payload)
		result := fmt.Sprintf("desktop-%x", h[:12])
		runtime.KeepAlive(payload)
		return result
	})
	streaming := measure("streaming_startup_name", func() string {
		name, err := DesktopDirectoryNameArchive(bytes.NewReader(image), int64(len(image)))
		if err != nil {
			t.Fatal(err)
		}
		return name
	})
	if legacy != streaming {
		t.Fatal("content identity changed")
	}
	t.Logf("archive_bytes=%d sha256=%x name=%s; diagnostic GC-disabled heap deltas, not OS working set or production peaks", len(image), sha256.Sum256(image), legacy)
	runtime.KeepAlive(image)
}
