package macconnection

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Generated only from historical release ZIPs whose full payload and every
// member matched their release manifest. It is evidence, not a name wildcard.
//
//go:embed retired-runtime-assets.json
var retiredRuntimeAssets []byte

// Caller holds the protected recovery-store launch lock, has completed network
// recovery, and excludes pending upgrade/rollback. Only exact historical asset
// hashes are removed. Current runtime, recovery journals, logs, generated driver
// directories and all unknown files are retained; never recurse into them.
func PruneRetiredRuntimes(parent string) (removed, preserved []string) {
	return pruneRetiredRuntimes(parent, runtimeName, retiredRuntimeAssets)
}

func pruneRetiredRuntimes(parent, current string, catalogue []byte) (removed, preserved []string) {
	var known map[string][]map[string]string
	if !safeRuntimeDirectory(parent) || json.Unmarshal(catalogue, &known) != nil {
		return nil, []string{"MAC_RUNTIME_CLEANUP_OWNERSHIP_UNAVAILABLE"}
	}
	names, err := recoveryRuntimeNames(parent)
	if err != nil {
		return nil, []string{"MAC_RUNTIME_CLEANUP_ENUMERATION_FAILED"}
	}
	for _, name := range names {
		if name == current {
			continue
		}
		dir := filepath.Join(parent, name)
		if _, err = os.Lstat(dir); os.IsNotExist(err) {
			continue
		}
		if !safeRuntimeDirectory(dir) {
			preserved = append(preserved, name+": redirected runtime preserved")
			continue
		}
		if _, err = os.Lstat(filepath.Join(dir, "owned-session.json")); !os.IsNotExist(err) {
			preserved = append(preserved, name+": recovery journal preserved")
			continue
		}
		hash := strings.TrimPrefix(name, "mac-runtime-")
		if len(hash) != 64 {
			hash, err = runtimeAssetHash(filepath.Join(dir, "suhang-usbnet.exe"))
			if os.IsNotExist(err) {
				continue
			} // Assets already removed; logs remain.
			if err != nil {
				preserved = append(preserved, name+": legacy executable unverified")
				continue
			}
		}
		inventories := known[hash]
		if len(inventories) == 0 {
			preserved = append(preserved, name+": unknown release preserved")
			continue
		}
		var files []string
		valid := false
		for _, inventory := range inventories {
			files = nil
			valid = true
			for asset, digest := range inventory {
				if asset != filepath.Base(asset) || asset == "." || asset == ".." || strings.ContainsAny(asset, "\\:/") {
					valid = false
					break
				}
				p := filepath.Join(dir, asset)
				actual, err := runtimeAssetHash(p)
				if os.IsNotExist(err) {
					continue
				}
				if err != nil || actual != digest {
					valid = false
					break
				}
				files = append(files, p)
			}
			if valid {
				break
			}
		}
		if !valid {
			preserved = append(preserved, name+": changed assets preserved")
			continue
		}
		sort.Strings(files)
		// Legacy layouts derive their retry identity from the executable; remove
		// it last so any earlier locked member leaves that identity available.
		exe := filepath.Join(dir, "suhang-usbnet.exe")
		for i, p := range files {
			if p == exe {
				files = append(append(files[:i:i], files[i+1:]...), exe)
				break
			}
		}
		failed := false
		for _, p := range files {
			if err = os.Remove(p); err != nil && !os.IsNotExist(err) {
				preserved = append(preserved, name+": asset in use; retry pending")
				failed = true
				break
			}
		}
		if failed {
			continue
		}
		if len(files) > 0 {
			removed = append(removed, name+": verified program assets")
		}
		// Removing an empty directory succeeds; retained logs/data keep theirs.
		_ = os.Remove(dir)
	}
	return removed, preserved
}

func runtimeAssetHash(path string) (string, error) {
	if _, err := os.Lstat(path); err != nil {
		return "", err
	}
	if !safeExisting(path) {
		return "", fmt.Errorf("redirected asset")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() > 32<<20 {
		return "", fmt.Errorf("asset size invalid")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, 32<<20+1))
	if err != nil || n != st.Size() {
		return "", fmt.Errorf("asset read failed")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
