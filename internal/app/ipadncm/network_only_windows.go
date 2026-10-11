//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type networkOnlyReceipt struct {
	Version            int                   `json:"version"`
	ServiceState       uint32                `json:"original_amds_state"`
	StartType          uint32                `json:"original_amds_start_type"`
	Nodes              []portableNodeReceipt `json:"portable_nodes,omitempty"`
	PersistentUSBOwner bool                  `json:"persistent_usb_owner,omitempty"`
}
type NetworkOnlyStatus struct {
	Enabled   bool   `json:"network_only"`
	Available bool   `json:"network_only_available"`
	Busy      bool   `json:"network_only_busy"`
	Status    string `json:"network_only_status"`
	Notice    string `json:"network_only_notice"`
}

var networkOnly struct {
	sync.Mutex
	dir, system                                  string
	available, enabled, pending, requested, busy bool
	networkOnlyOperationState
}

// Retired API names remain only so old fixed diagnostics cannot recreate policy.
func InitNetworkOnly(dir, system string, available bool) error {
	return fmt.Errorf("LEGACY_ISOLATION_REMOVED")
}
func NetworkOnlyCanConnect() bool {
	networkOnly.Lock()
	defer networkOnly.Unlock()
	return !networkOnly.blocked
}
func NetworkOnlyAvailable() bool { return false }
func NetworkOnlyEnabled() bool   { return false }
func NetworkOnlySnapshot() NetworkOnlyStatus {
	networkOnly.Lock()
	defer networkOnly.Unlock()
	return NetworkOnlyStatus{Status: networkOnly.status, Notice: networkOnly.notice}
}
func NetworkOnlyPending() bool                                         { return false }
func RequestNetworkOnly(enabled bool) error                            { return fmt.Errorf("LEGACY_ISOLATION_REMOVED") }
func RunPendingNetworkOnly(ctx context.Context, cleanupSafe bool) bool { return false }
func PrepareNetworkOnlyStartup(ctx context.Context) error              { return nil }
func EnsureNetworkOnly(ctx context.Context, s Snapshot) error {
	return fmt.Errorf("LEGACY_ISOLATION_REMOVED")
}
func EnsureNetworkOnlyForPhase(ctx context.Context, s Snapshot, phase string) error {
	return fmt.Errorf("LEGACY_ISOLATION_REMOVED")
}
func applyNetworkOnlyService(ctx context.Context, dir string) error {
	return fmt.Errorf("LEGACY_ISOLATION_REMOVED")
}

func readNetworkOnlyReceipt(dir string) (networkOnlyReceipt, error) {
	var r networkOnlyReceipt
	b, e := readProtectedNetworkOnlyFile(filepath.Join(dir, "network-only-receipt.json"), 65536)
	if e != nil {
		return r, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var tail any
	if d.Decode(&r) != nil || !validUnpairedReceiptSchema(r.Version, r.PersistentUSBOwner) || (r.ServiceState != uint32(svc.Running) && r.ServiceState != uint32(svc.Stopped)) || r.StartType > 4 || len(r.Nodes) > 64 || d.Decode(&tail) != io.EOF {
		return r, fmt.Errorf("network-only receipt invalid")
	}
	seen := map[string]bool{}
	for _, n := range r.Nodes {
		if !validPortableReceipt(n) || seen[strings.ToUpper(n.ID)] {
			return r, fmt.Errorf("portable receipt invalid")
		}
		seen[strings.ToUpper(n.ID)] = true
	}
	if r.PersistentUSBOwner {
		o, e := readUnpairedProductOwner(dir)
		if e != nil || !unpairedProductReceiptRoots(r, o) {
			return r, fmt.Errorf("persistent USB originals lack exact protected owner")
		}
		if _, e := readOwnedUnpairedProductChoice(dir); e != nil && !SimplifiedIPadNetworkConfigured() {
			return r, e
		}
	}
	return r, nil
}
func saveNetworkOnlyReceipt(dir string, r networkOnlyReceipt) error {
	b, e := json.Marshal(r)
	if len(b) > 65536 {
		return fmt.Errorf("network-only receipt size limit")
	}
	if e != nil {
		return e
	}
	return writeNetworkOnlyFile(dir, "network-only-receipt.json", b, true)
}

func writeNetworkOnlyFile(dir, name string, b []byte, replace bool) error {
	f, e := os.CreateTemp(dir, "network-only-owned-*.tmp")
	if e != nil {
		return e
	}
	path := f.Name()
	defer os.Remove(path)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	from, _ := windows.UTF16PtrFromString(path)
	to, _ := windows.UTF16PtrFromString(filepath.Join(dir, name))
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(from, to, flags)
}

func readProtectedNetworkOnlyFile(path string, limit int64) ([]byte, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	var info windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(h, &info); e != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("unsafe network-only receipt")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("receipt handle unavailable")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, fmt.Errorf("receipt size or read failed")
	}
	return b, nil
}

// Only the bounded migration may consume AMDS/WPD originals. Generic old
// restore commands are retired so they cannot restore grouping or reopen policy.
func RestoreNetworkOnlyPortableNodes(dir string) error {
	return fmt.Errorf("LEGACY_ISOLATION_MIGRATION_ONLY")
}
func RestoreNetworkOnly(dir, system string) error {
	return fmt.Errorf("LEGACY_ISOLATION_MIGRATION_ONLY")
}
