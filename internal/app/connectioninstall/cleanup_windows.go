//go:build windows && amd64

package connectioninstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"suhang/usbnet/internal/platform/windows/installcleanup"
	"sync"
	"time"
)

// Serialize received release publication with cleanup of prior staged copies.
var installationCleanupMu sync.Mutex
var desktopNamePattern = regexp.MustCompile(`^desktop-[a-f0-9]{24}$`)

type InstallationCleanupReport struct {
	Version   string   `json:"version"`
	Removed   []string `json:"removed,omitempty"`
	Preserved []string `json:"preserved,omitempty"`
	Pending   bool     `json:"pending"`
}

func DesktopDirectoryName(payload []byte) string {
	h := sha256.Sum256(payload)
	return fmt.Sprintf("desktop-%x", h[:12])
}

// Run after startup registration and network recovery. Only older executable
// versions, sealed desktop runtimes and verified received installer copies are
// candidates. Settings, certificates, shared/received files and drivers stay.
func cleanupInstallation(current, desktop string, runtimeCleanup func() ([]string, []string)) InstallationCleanupReport {
	r := InstallationCleanupReport{Version: current}
	held := func(name, reason string) { r.Preserved = append(r.Preserved, name+": "+reason); r.Pending = true }
	if !installationCleanupMu.TryLock() {
		held("upgrade", "received release publication in progress")
		return r
	}
	defer installationCleanupMu.Unlock()
	root, err := protectedRoot(false)
	if err != nil || !versionPattern.MatchString(current) || !desktopNamePattern.MatchString(desktop) {
		held("installation", "ownership unavailable")
		return r
	}
	if err = Verify(filepath.Join(root, current, BinaryName)); err != nil {
		held("installation", "current executable verification failed")
		return r
	}
	maintenance, err := remoteRoot()
	if err != nil {
		held("maintenance", "ownership unavailable")
		return r
	}
	if _, pending, transitionError := readCoreTransition(); transitionError != nil || pending {
		held("core service", "owned service transition dependencies retained")
		return r
	}
	if binding, bound, bindingError := readCoreBinding(); bindingError != nil {
		held("core service", "owner binding unverified")
		return r
	} else if bound && filepath.Base(filepath.Dir(binding.Executable)) != current {
		held("core service", "service still references a different executable version")
		return r
	}
	var job UpdateJob
	err = readRemote(filepath.Join(maintenance, "job.json"), &job)
	if err != nil && !os.IsNotExist(err) {
		held("upgrade", "journal unreadable")
		return r
	}
	if err == nil && !installcleanup.UpdateTerminal(job.Status) {
		held("upgrade", "rollback dependencies still required")
		return r
	}
	// Serialize against product Task mutations and canonical dependency repair.
	startupTaskLock.Lock()
	defer startupTaskLock.Unlock()
	dependencyCtx, dependencyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	taskTargets, taskDependencyError := nativeStartupDependencies(dependencyCtx, filepath.Join(root, current, BinaryName))
	dependencyCancel()

	roots := []struct{ path, binary string }{{root, BinaryName}}
	old, err := legacyRoot()
	if err == nil && !strings.EqualFold(old, root) {
		if _, err = os.Lstat(old); err == nil {
			if _, err = protectedRootAt(old, false); err != nil {
				held("legacy", "ownership unavailable")
			} else {
				roots = append(roots, struct{ path, binary string }{old, LegacyBinaryName})
			}
		} else if !os.IsNotExist(err) {
			held("legacy", "enumeration failed")
		}
	}
	type candidate struct {
		dir, marker string
		files       map[string]string
	}
	var versions, desktops []candidate
	rollbackVersion := ""
	knownHashes := map[string]bool{}
	for _, base := range roots {
		entries, err := os.ReadDir(base.path)
		if err != nil {
			held(filepath.Base(base.path), "enumeration failed")
			continue
		}
		for _, entry := range entries {
			dir := filepath.Join(base.path, entry.Name())
			if versionPattern.MatchString(entry.Name()) {
				receipt, err := readReceipt(dir)
				if err != nil {
					held(entry.Name(), "invalid ownership receipt")
					continue
				}
				inv := map[string]string{base.binary: receipt.SHA}
				if _, err = installcleanup.Files(dir, "ownership.json", inv, 256<<20, cleanupSafePath); err != nil {
					held(entry.Name(), err.Error())
					continue
				}
				knownHashes[receipt.SHA] = true
				if installcleanup.OlderVersion(entry.Name(), current) && (rollbackVersion == "" || installcleanup.OlderVersion(rollbackVersion, entry.Name())) {
					rollbackVersion = entry.Name()
				}
				if installcleanup.OlderVersion(entry.Name(), current) {
					if reason := startupDependencyRetentionReason(taskTargets, filepath.Join(dir, base.binary), taskDependencyError); reason != "" {
						held(entry.Name(), reason)
						continue
					}
					versions = append(versions, candidate{dir, "ownership.json", inv})
				}
			} else if desktopNamePattern.MatchString(entry.Name()) {
				files, err := desktopInventory(dir)
				if err != nil {
					held(entry.Name(), err.Error())
					continue
				}
				desktops = append(desktops, candidate{dir, "desktop-ownership.json", files})
			}
		}
	}
	if job.Manifest.Version == current && job.Status == "complete" && job.Old != "" && Verify(job.Old) == nil {
		rollbackVersion = filepath.Base(filepath.Dir(job.Old))
	}
	// The readable desktop tree shares release versions with the core. Keep the
	// previous verified release alongside the current one for local rollback.
	desktopRoot := filepath.Join(root, "Desktop")
	if _, err := os.Lstat(desktopRoot); err == nil {
		if _, err = protectedRootAt(desktopRoot, false); err != nil {
			held("Desktop", "ownership unavailable")
		} else {
			entries, err := os.ReadDir(desktopRoot)
			if err != nil {
				held("Desktop", "enumeration failed")
			} else {
				for _, entry := range entries {
					if !entry.IsDir() || !versionPattern.MatchString(entry.Name()) || !installcleanup.OlderVersion(entry.Name(), current) || entry.Name() == rollbackVersion {
						continue
					}
					dir := filepath.Join(desktopRoot, entry.Name())
					files, err := desktopInventory(dir)
					if err != nil {
						held("Desktop/"+entry.Name(), err.Error())
						continue
					}
					desktops = append(desktops, candidate{dir, "desktop-ownership.json", files})
				}
			}
		}
	} else if !os.IsNotExist(err) {
		held("Desktop", "enumeration failed")
	}
	remove := func(c candidate) {
		files, err := installcleanup.Files(c.dir, c.marker, c.files, 256<<20, cleanupSafePath)
		if err == nil {
			err = installcleanup.Remove(c.dir, files, os.Remove)
		}
		if err != nil {
			held(filepath.Base(c.dir), err.Error())
		} else {
			r.Removed = append(r.Removed, filepath.Base(c.dir))
		}
	}
	// Older received copies can be identified by exact installed receipts. Seal
	// that inventory before removal so interrupted deletion remains retryable.
	entries, err := os.ReadDir(maintenance)
	if err != nil {
		held("staged releases", "enumeration failed")
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "release-") {
			continue
		}
		dir := filepath.Join(maintenance, entry.Name())
		marker := filepath.Join(dir, "cleanup-ownership.json")
		var receipt struct {
			Product string `json:"product"`
			SHA     string `json:"sha256"`
		}
		err := readRemote(marker, &receipt)
		if os.IsNotExist(err) {
			sha, e := fileHash(filepath.Join(dir, "release.exe"))
			contents, re := os.ReadDir(dir)
			if noReparse(dir) != nil || e != nil || re != nil || len(contents) != 1 || !knownHashes[sha] {
				held(entry.Name(), "unverified received copy")
				continue
			}
			receipt.Product, receipt.SHA = ProductID, sha
			err = writeRemote(marker, receipt)
		}
		hash, de := hex.DecodeString(receipt.SHA)
		if err != nil || receipt.Product != ProductID || de != nil || len(hash) != sha256.Size {
			held(entry.Name(), "invalid received copy receipt")
			continue
		}
		remove(candidate{dir, "cleanup-ownership.json", map[string]string{"release.exe": receipt.SHA}})
	}
	for _, c := range desktops {
		remove(c)
	}
	for _, c := range versions {
		if filepath.Base(c.dir) == rollbackVersion {
			continue
		}
		// A foreign scheduler writer is not covered by our mutex. Re-observe the
		// exact tasks immediately before each executable deletion; any read
		// failure retains this and every remaining prior version.
		if taskDependencyError == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			taskTargets, taskDependencyError = nativeStartupDependencies(ctx, filepath.Join(root, current, BinaryName))
			cancel()
		}
		var target string
		for name := range c.files {
			target = filepath.Join(c.dir, name)
		}
		if reason := startupDependencyRetentionReason(taskTargets, target, taskDependencyError); reason != "" {
			held(filepath.Base(c.dir), reason)
			continue
		}
		remove(c)
	}
	if runtimeCleanup != nil {
		removed, preserved := runtimeCleanup()
		r.Removed = append(r.Removed, removed...)
		for _, reason := range preserved {
			held("Mac runtime", reason)
		}
	}
	return r
}

func cleanupSafePath(path string) bool { return noReparse(path) == nil }

// Locked old UI/worker files are retried after their normal exit. No process is
// killed and no permanent reboot deletion is queued for a rollback executable.
func StartInstallationCleanup(parent context.Context, current, desktop string, runtimeCleanup func() ([]string, []string)) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var removed []string
		for _, delay := range []time.Duration{0, 10 * time.Second, 30 * time.Second, 60 * time.Second, 120 * time.Second} {
			if delay != 0 {
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
			if ctx.Err() != nil {
				return
			}
			report := cleanupInstallation(current, desktop, runtimeCleanup)
			removed = append(removed, report.Removed...)
			report.Removed = removed
			if root, err := protectedRoot(false); err == nil {
				_ = writeRemote(filepath.Join(root, "installation-cleanup.json"), report)
			}
			if !report.Pending {
				return
			}
		}
	}()
	return func() { cancel(); <-done }
}

func desktopInventory(dir string) (map[string]string, error) {
	if noReparse(dir) != nil || noReparse(filepath.Join(dir, "desktop-ownership.json")) != nil {
		return nil, fmt.Errorf("desktop ownership unavailable")
	}
	b, err := os.ReadFile(filepath.Join(dir, "desktop-ownership.json"))
	if err != nil || len(b) > 128<<10 {
		return nil, fmt.Errorf("desktop marker invalid")
	}
	var r struct {
		Product string            `json:"product"`
		Files   map[string]string `json:"files"`
	}
	if json.Unmarshal(b, &r) != nil || r.Product != ProductID || len(r.Files) < 1 {
		return nil, fmt.Errorf("desktop ownership invalid")
	}
	return r.Files, nil
}

func InstallationCleanupStatus() any {
	root, err := protectedRoot(false)
	if err != nil {
		return map[string]string{"status": "unavailable"}
	}
	var report InstallationCleanupReport
	if err = readRemote(filepath.Join(root, "installation-cleanup.json"), &report); err != nil {
		return map[string]string{"status": "not_recorded"}
	}
	return report
}
