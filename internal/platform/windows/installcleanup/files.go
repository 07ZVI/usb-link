// Package installcleanup validates sealed file inventories before deletion.
package installcleanup

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// OlderVersion compares release components numerically, never lexically.
func OlderVersion(candidate, current string) bool {
	a, b := strings.Split(candidate, "."), strings.Split(current, ".")
	if len(a) != 3 || len(b) != 3 {
		return false
	}
	var av, bv [3]uint64
	for i := range a {
		var err error
		av[i], err = strconv.ParseUint(a[i], 10, 64)
		if err != nil {
			return false
		}
		bv[i], err = strconv.ParseUint(b[i], 10, 64)
		if err != nil {
			return false
		}
	}
	for i := range av {
		if av[i] != bv[i] {
			return av[i] < bv[i]
		}
	}
	return false
}

// Only explicit terminal update states permit deleting rollback dependencies.
// An unreadable journal or a future/unknown state must not be treated as idle.
func UpdateTerminal(status string) bool {
	switch status {
	case "complete", "failed", "rollback", "declined":
		return true
	}
	return false
}

// Files validates all remaining inventory members before returning anything.
// Missing members permit retry after interrupted deletion; unknown or modified
// members preserve the entire directory. safe must reject redirected paths.
func Files(dir, marker string, inventory map[string]string, limit int64, safe func(string) bool) ([]string, error) {
	if !safe(dir) || !safe(filepath.Join(dir, marker)) || len(inventory) == 0 {
		return nil, fmt.Errorf("ownership unavailable")
	}
	for name, digest := range inventory {
		decoded, err := hex.DecodeString(digest)
		if name == "." || name == ".." || name == marker || name != filepath.Base(name) || strings.ContainsAny(name, "\\:/") || err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("invalid inventory")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if entry.Name() == marker {
			continue
		}
		digest, known := inventory[entry.Name()]
		p := filepath.Join(dir, entry.Name())
		if !known || entry.IsDir() || !safe(p) {
			return nil, fmt.Errorf("unknown contents preserved")
		}
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
			f.Close()
			return nil, fmt.Errorf("invalid file")
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(f, limit+1))
		f.Close()
		if err != nil || n != st.Size() || hex.EncodeToString(h.Sum(nil)) != digest {
			return nil, fmt.Errorf("changed contents preserved")
		}
		files = append(files, p)
	}
	sort.Strings(files)
	// Ownership is deleted last, so locked files retain a retryable inventory.
	return append(files, filepath.Join(dir, marker)), nil
}

func Remove(dir string, files []string, remove func(string) error) error {
	for _, p := range files {
		if err := remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return remove(dir)
}
