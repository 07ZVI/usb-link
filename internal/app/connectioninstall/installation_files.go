package connectioninstall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// The same real file algorithm is exercised in portable crash/occupancy tests.
// Production supplies Windows handle/ACL/hard-link protection and a native
// no-replace durable rename. Filename patterns never supply ownership by themselves.
type installationFiles struct {
	protect func(string, bool) error
	publish func(string, string) error
}

// Inventory is complete and flat except for the publisher-owned Desktop tree.
// No wildcard, recursive deletion, arbitrary path or unknown content is admitted.
func (fs installationFiles) inventory(dir string) (map[string]string, error) {
	inv := map[string]string{}
	e := filepath.WalkDir(dir, func(p string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if fs.protect(p, de.IsDir()) != nil {
			return fmt.Errorf("INSTALL_RELEASE_REDIRECTED")
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if de.IsDir() {
			if e := fs.protect(p, true); e != nil {
				return e
			}
			if rel == "." || rel == "Desktop" {
				return nil
			}
			return fmt.Errorf("INSTALL_UNKNOWN_DIRECTORY_PRESERVED")
		}
		if !safeInstallationFile(rel) || len(inv) >= 1024 {
			return fmt.Errorf("INSTALL_UNKNOWN_FILE_PRESERVED")
		}
		sum, err := fs.hash(p)
		if err != nil {
			return err
		}
		inv[rel] = sum
		return nil
	})
	return inv, e
}
func (fs installationFiles) hash(path string) (string, error) {
	if e := fs.protect(path, false); e != nil {
		return "", e
	}
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() > 256<<20 {
		return "", fmt.Errorf("INSTALL_FILE_SIZE_INVALID")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (256<<20)+1))
	if e != nil || n != s.Size() {
		return "", fmt.Errorf("INSTALL_FILE_READ_FAILED")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (fs installationFiles) verify(dir string, want map[string]string, partial bool) error {
	if _, e := os.Lstat(dir); os.IsNotExist(e) && partial {
		return nil
	}
	got, e := fs.inventory(dir)
	if e != nil {
		return e
	}
	for n, h := range got {
		if want[n] != h {
			return fmt.Errorf("INSTALL_FILE_CHANGED: %s", n)
		}
	}
	if !partial && !reflect.DeepEqual(got, want) {
		return fmt.Errorf("INSTALL_RELEASE_INCOMPLETE")
	}
	return nil
}
func (fs installationFiles) copy(from, to, sum string) error {
	return fs.write(to, sum, func() (io.ReadCloser, error) {
		if fs.protect(from, false) != nil {
			return nil, fmt.Errorf("INSTALL_COPY_SOURCE_REDIRECTED")
		}
		return os.Open(from)
	})
}
func (fs installationFiles) write(to, sum string, open func() (io.ReadCloser, error)) error {
	if got, e := fs.hash(to); e == nil {
		if got == sum {
			return nil
		}
		return fmt.Errorf("INSTALL_DESTINATION_CHANGED")
	} else if !os.IsNotExist(e) {
		return e
	}
	part := to + ".part"
	if _, e := os.Lstat(part); e == nil {
		// A crash may leave a prefix. Only bytes proven to be an exact prefix of
		// this immutable source are removed; a renamed/changed file is preserved.
		if e = fs.prefix(part, open); e != nil {
			return e
		}
		if e = os.Remove(part); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	in, e := open()
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(part, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = io.Copy(out, io.LimitReader(in, (256<<20)+1))
	if e == nil {
		e = out.Sync()
	}
	e = errors.Join(e, out.Close())
	if e != nil {
		return e
	}
	got, e := fs.hash(part)
	if e != nil || got != sum {
		return fmt.Errorf("INSTALL_COPY_HASH_CHANGED")
	}
	return fs.publish(part, to)
}
func (fs installationFiles) prefix(part string, open func() (io.ReadCloser, error)) error {
	if e := fs.protect(part, false); e != nil {
		return e
	}
	f, e := os.Open(part)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || st.Size() > 256<<20 {
		return fmt.Errorf("INSTALL_PARTIAL_SIZE_CHANGED")
	}
	in, e := open()
	if e != nil {
		return e
	}
	defer in.Close()
	a := make([]byte, 32768)
	b := make([]byte, 32768)
	for left := st.Size(); left > 0; {
		n := min(left, int64(len(a)))
		if _, e = io.ReadFull(f, a[:n]); e != nil {
			return e
		}
		if _, e = io.ReadFull(in, b[:n]); e != nil || !bytes.Equal(a[:n], b[:n]) {
			return fmt.Errorf("INSTALL_PARTIAL_CONTENT_CHANGED")
		}
		left -= n
	}
	return nil
}
func (fs installationFiles) cleanPartials(from, to string, inv map[string]string) error {
	for n := range inv {
		part := filepath.Join(to, filepath.FromSlash(n)) + ".part"
		if _, e := os.Lstat(part); os.IsNotExist(e) {
			continue
		} else if e != nil {
			return e
		}
		source := filepath.Join(from, filepath.FromSlash(n))
		if e := fs.prefix(part, func() (io.ReadCloser, error) { return os.Open(source) }); e != nil {
			return e
		}
		if e := os.Remove(part); e != nil {
			return e
		}
	}
	return nil
}

func (fs installationFiles) clone(from, to string, inv map[string]string) error {
	if e := fs.mkdir(to); e != nil {
		return e
	}
	if e := fs.verify(from, inv, false); e != nil {
		return e
	}
	if e := fs.cleanPartials(from, to, inv); e != nil {
		return e
	}
	if e := fs.verify(to, inv, true); e != nil {
		return e
	}
	names := make([]string, 0, len(inv))
	for n := range inv {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		target := filepath.Join(to, filepath.FromSlash(n))
		if strings.HasPrefix(n, "Desktop/") {
			if e := fs.mkdir(filepath.Join(to, "Desktop")); e != nil {
				return e
			}
		}
		if e := fs.copy(filepath.Join(from, filepath.FromSlash(n)), target, inv[n]); e != nil {
			return e
		}
	}
	return fs.verify(to, inv, false)
}
func (fs installationFiles) mkdir(p string) error {
	if e := os.Mkdir(p, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	return fs.protect(p, true)
}
func (fs installationFiles) remove(dir string, inv map[string]string) error {
	if e := fs.verify(dir, inv, true); e != nil {
		return e
	}
	names := make([]string, 0, len(inv))
	for n := range inv {
		names = append(names, n)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	for _, n := range names {
		p := filepath.Join(dir, filepath.FromSlash(n))
		if e := os.Remove(p); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	for _, p := range []string{filepath.Join(dir, "Desktop"), dir} {
		if e := os.Remove(p); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	return nil
}
