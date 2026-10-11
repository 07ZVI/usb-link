package macconnection

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyDLLSearchStaysInRuntimeDirectoriesAndRejectsChanges(t *testing.T) {
	data := []byte("pinned DLL fixture")
	h := sha256.Sum256(data)
	want := hex.EncodeToString(h[:])
	for _, kind := range []string{"valid", "changed", "unknown-dir", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			name := runtimeDirectoryName(strings.Repeat("b", 64))
			if kind == "unknown-dir" {
				name = "other-runtime"
			}
			dir := filepath.Join(parent, name)
			os.Mkdir(dir, 0700)
			path := filepath.Join(dir, "wintun.dll")
			os.WriteFile(path, data, 0600)
			if kind == "changed" {
				os.WriteFile(path, []byte("changed"), 0600)
			}
			if kind == "symlink" {
				os.Rename(path, path+".real")
				if err := os.Symlink(path+".real", path); err != nil {
					t.Skip(err)
				}
			}
			got := pinnedLegacyWintun(parent, want)
			if kind == "valid" {
				if got != path {
					t.Fatal("old owner DLL not found")
				}
			} else if got != "" {
				t.Fatal("unverified DLL admitted")
			}
		})
	}
}
