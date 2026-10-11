package connectioninstall

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const desktopEntryLimit = 80 << 20

// DesktopDirectoryNameArchive hashes the immutable embedded image in place.
// The caller keeps reader alive throughout preparation; it must not change.
func DesktopDirectoryNameArchive(reader io.ReaderAt, size int64) (string, error) {
	if reader == nil || size <= 0 {
		return "", fmt.Errorf("invalid desktop archive")
	}
	h := sha256.New()
	n, err := io.CopyBuffer(h, io.NewSectionReader(reader, 0, size), make([]byte, 32<<10))
	if err != nil {
		return "", fmt.Errorf("desktop archive hash failed: %w", err)
	}
	if n != size {
		return "", fmt.Errorf("desktop archive truncated")
	}
	return fmt.Sprintf("desktop-%x", h.Sum(nil)[:12]), nil
}

// prepareDesktopEntries keeps decompression and independent disk readback
// bounded. safePath is the existing platform ownership/reparse guard.
func prepareDesktopEntries(z *zip.Reader, dir string, fresh bool, safePath func(string) error) error {
	names := map[string]bool{}
	var total uint64
	buf := make([]byte, 32<<10)
	for _, entry := range z.File {
		name := entry.Name
		if name == "" || name == "." || name == ".." || name != filepath.Base(name) || strings.ContainsAny(name, "\\:/") || !entry.Mode().IsRegular() || entry.UncompressedSize64 > desktopEntryLimit || names[strings.ToLower(name)] {
			return fmt.Errorf("invalid desktop payload entry")
		}
		names[strings.ToLower(name)] = true
		total += entry.UncompressedSize64
		if total > 300<<20 {
			return fmt.Errorf("desktop payload too large")
		}
		path := filepath.Join(dir, name)
		if !fresh {
			if err := safePath(path); err != nil {
				return fmt.Errorf("desktop file redirected: %w", err)
			}
		}
		input, err := entry.Open()
		if err != nil {
			return err
		}
		want := sha256.New()
		var output *os.File
		var dst io.Writer = want
		if fresh {
			output, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				input.Close()
				return err
			}
			dst = io.MultiWriter(want, output)
		}
		n, copyErr := io.CopyBuffer(dst, io.LimitReader(input, desktopEntryLimit+1), buf)
		input.Close()
		var closeErr error
		if output != nil {
			closeErr = output.Close()
		}
		// Reaching archive EOF also validates its CRC, even for existing files.
		if copyErr != nil || uint64(n) != entry.UncompressedSize64 {
			return fmt.Errorf("desktop payload damaged")
		}
		if closeErr != nil {
			return closeErr
		}
		if err = safePath(path); err != nil {
			return fmt.Errorf("desktop file redirected: %w", err)
		}
		actual, err := os.Open(path)
		if err != nil {
			return err
		}
		info, err := actual.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() != n {
			actual.Close()
			return fmt.Errorf("desktop file verification failed")
		}
		got := sha256.New()
		read, readErr := io.CopyBuffer(got, io.LimitReader(actual, desktopEntryLimit+1), buf)
		actual.Close()
		if readErr != nil || read != n || !bytes.Equal(got.Sum(nil), want.Sum(nil)) {
			return fmt.Errorf("desktop file verification failed")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != len(names) || !names["usblink.desktop.exe"] {
		return fmt.Errorf("desktop directory does not match payload")
	}
	return nil
}
