package macconnection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRetiredRuntimeAssetsAndLogs(t *testing.T) {
	parent := t.TempDir()
	exe := []byte("old executable")
	h := sha256.Sum256(exe)
	hash := hex.EncodeToString(h[:])
	name := runtimeDirectoryName(hash)
	dir := filepath.Join(parent, name)
	os.Mkdir(dir, 0700)
	dll := []byte("old dll")
	d := sha256.Sum256(dll)
	inv := map[string]string{"suhang-usbnet.exe": hash, "wintun.dll": hex.EncodeToString(d[:])}
	catalogue, _ := json.Marshal(map[string][]map[string]string{hash: {inv}})
	for _, tc := range []string{"current", "journal", "modified", "retired"} {
		t.Run(tc, func(t *testing.T) {
			os.WriteFile(filepath.Join(dir, "suhang-usbnet.exe"), exe, 0600)
			os.WriteFile(filepath.Join(dir, "wintun.dll"), dll, 0600)
			os.WriteFile(filepath.Join(dir, "installer.log"), []byte("keep diagnostics"), 0600)
			os.WriteFile(filepath.Join(dir, "user.txt"), []byte("unknown data"), 0600)
			current := "mac-runtime-other"
			if tc == "current" {
				current = name
			}
			if tc == "journal" {
				os.WriteFile(filepath.Join(dir, "owned-session.json"), []byte("pending"), 0600)
			}
			if tc == "modified" {
				os.WriteFile(filepath.Join(dir, "wintun.dll"), []byte("changed"), 0600)
			}
			removed, _ := pruneRetiredRuntimes(parent, current, catalogue)
			if tc == "retired" {
				if len(removed) != 1 {
					t.Fatal(removed)
				}
				if _, err := os.Stat(filepath.Join(dir, "suhang-usbnet.exe")); !os.IsNotExist(err) {
					t.Fatal("old executable left", err)
				}
			} else {
				if len(removed) != 0 {
					t.Fatal("active/unsafe runtime removed")
				}
				if _, err := os.Stat(filepath.Join(dir, "suhang-usbnet.exe")); err != nil {
					t.Fatal(err)
				}
			}
			for _, file := range []string{"installer.log", "user.txt"} {
				if _, err := os.Stat(filepath.Join(dir, file)); err != nil {
					t.Fatal("data removed", err)
				}
			}
			os.Remove(filepath.Join(dir, "owned-session.json"))
		})
	}
}

func TestRetiredCatalogueIdentities(t *testing.T) {
	var catalogue map[string][]map[string]string
	if err := json.Unmarshal(retiredRuntimeAssets, &catalogue); err != nil {
		t.Fatal(err)
	}
	if len(catalogue) == 0 {
		t.Fatal("empty release catalogue")
	}
	for hash, inventories := range catalogue {
		for _, inv := range inventories {
			if inv["suhang-usbnet.exe"] != hash {
				t.Fatal("bridge identity mismatch")
			}
			for _, digest := range inv {
				b, err := hex.DecodeString(digest)
				if err != nil || len(b) != 32 {
					t.Fatal("invalid asset hash")
				}
			}
		}
	}
}
