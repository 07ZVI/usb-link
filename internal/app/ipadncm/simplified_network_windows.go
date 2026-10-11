//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// This is the sole compatibility entry point for retired AMDS/WPD protection.
// Missing originals are never inferred from a setting, owner or current state.
// Failure affects only iPad admission; Mac diagnostics and signed upgrade stay live.
func InitSimplifiedIPadNetwork(dir string) error {
	legacySystemOriginalsVerified.Store(false)
	simplifiedMigrationProblem.Store("")
	simplifiedNetworkConfigured.Store(true)
	simplifiedNetworkFeatures.Store(false)
	unpairedProductConfigured.Store(false)
	unpairedProductFeatures.Store(false)
	networkOnly.Lock()
	networkOnly.dir, networkOnly.available, networkOnly.enabled = dir, false, false
	networkOnly.pending, networkOnly.busy, networkOnly.blocked = false, false, false
	networkOnly.status, networkOnly.notice = "SIMPLIFIED_NETWORK", "iPad 詢問是否信任時，請點不信任。"
	networkOnly.Unlock()
	e := migrateLegacyIPadIsolation(dir)
	if e != nil {
		simplifiedMigrationProblem.Store("LEGACY_ISOLATION_ORIGINALS_UNVERIFIED")
		networkOnly.Lock()
		networkOnly.blocked, networkOnly.status, networkOnly.notice = !legacySystemOriginalsVerified.Load(), "LEGACY_ISOLATION_MIGRATION_PENDING", "舊版 iPad 設定尚未核對還原，已暫停 iPad 接入；Mac 管理連線保留。請保留配對檔案備份，查看診斷並更新簽名修正版；不要自行刪除恢復記錄。"
		if legacySystemOriginalsVerified.Load() {
			networkOnly.status, networkOnly.notice = "LEGACY_METADATA_CLEANUP_PENDING", "AMDS/WPD 已核對恢復；舊中繼資料清理尚未完成，記錄保留。"
		}
		networkOnly.Unlock()
	}
	return e
}

const simplifiedMigrationFile = "retired-isolation-migration.json"

var legacySystemOriginalsVerified atomic.Bool
var simplifiedGroupingWarning atomic.Value
var simplifiedMigrationProblem atomic.Value

func migrationProblemCode() string { p, _ := simplifiedMigrationProblem.Load().(string); return p }

func RecordSimplifiedGroupingWarning(problem string) { simplifiedGroupingWarning.Store(problem) }

func migrationComplete(dir string) (bool, error) {
	b, e := readPortableProtectedFile(filepath.Join(dir, simplifiedMigrationFile), 1024)
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	var p struct {
		Version   int  `json:"version"`
		Completed bool `json:"completed"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var tail any
	if d.Decode(&p) != nil || p.Version != 1 || !p.Completed || d.Decode(&tail) != io.EOF {
		return false, fmt.Errorf("LEGACY_MIGRATION_MARKER_INVALID")
	}
	return true, nil
}
func legacyObligationsAbsent(dir string) (bool, error) {
	absent := true
	for _, name := range []string{"network-only-receipt.json", portablePropertyOriginalFile, "amds-diagnostic.json"} {
		p, e := windows.UTF16PtrFromString(filepath.Join(dir, name))
		if e != nil {
			return false, e
		}
		attrs, e := windows.GetFileAttributes(p)
		if e == windows.ERROR_FILE_NOT_FOUND {
			continue
		}
		if e != nil || attrs&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
			return false, fmt.Errorf("LEGACY_ORIGINAL_METADATA_UNVERIFIED")
		}
		absent = false
	}
	return absent, nil
}
func markMigrationComplete(dir string) error {
	if done, e := migrationComplete(dir); e != nil {
		return e
	} else if done {
		return nil
	}
	if e := writePortableProtectedFile(dir, simplifiedMigrationFile, []byte(`{"version":1,"completed":true}`), false); e != nil {
		return e
	}
	ok, e := migrationComplete(dir)
	if e != nil || !ok {
		return fmt.Errorf("LEGACY_MIGRATION_MARKER_READBACK_FAILED")
	}
	return nil
}
func migrateLegacyIPadIsolation(dir string) error {
	if !networkOnlyDriverStoreProtected(dir) {
		return fmt.Errorf("LEGACY_ISOLATION_STORE_UNPROVEN")
	}
	done, e := migrationComplete(dir)
	if e != nil {
		return e
	}
	if done {
		absent, e := legacyObligationsAbsent(dir)
		if e != nil {
			return e
		}
		if absent {
			legacySystemOriginalsVerified.Store(true)
			return nil
		}
	}
	r, e := readNetworkOnlyReceipt(dir)
	if os.IsNotExist(e) {
		original, oe := readPortableOriginalStore(dir)
		if oe != nil || len(original.Records) != 0 {
			return fmt.Errorf("LEGACY_PORTABLE_ORIGINALS_WITHOUT_RECEIPT")
		}
		if e := RecoverAMDSModeDiagnostic(dir); e != nil {
			return e
		}
		legacySystemOriginalsVerified.Store(true)
		if e := retireLegacyIsolationMetadata(dir); e != nil {
			return e
		}
		return markMigrationComplete(dir)
	}
	if e != nil {
		return e
	}
	// Two AMDS original-value sources are ambiguous, never choose one after mutation.
	if _, de := readAMDSDiagnosticReceipt(filepath.Join(dir, "amds-diagnostic.json")); !os.IsNotExist(de) {
		return fmt.Errorf("LEGACY_AMDS_ORIGINALS_AMBIGUOUS")
	}
	return runLegacyIsolationMigration(func() error {
		return restorePortableNodeReceipts(r.Nodes, func(n portableNodeReceipt) error { return restoreOwnedPortableNode(dir, n) }, func(remaining []portableNodeReceipt) error {
			r.Nodes = remaining
			if e := saveNetworkOnlyReceipt(dir, r); e != nil {
				return e
			}
			return removeCheckpointedPortableOriginals(dir, remaining)
		})
	}, func() error {
		// An orphan sidecar is not an original that can be silently discarded.
		originals, e := readPortableOriginalStore(dir)
		if e != nil || len(originals.Records) != 0 {
			return fmt.Errorf("LEGACY_PORTABLE_ORIGINALS_STILL_PENDING")
		}
		if e := restoreLegacyAMDSOriginal(r); e != nil {
			return e
		}
		legacySystemOriginalsVerified.Store(true)
		return nil
	}, func() error {
		if e := os.Remove(filepath.Join(dir, "network-only-receipt.json")); e != nil {
			return e
		}
		if _, e := readNetworkOnlyReceipt(dir); !os.IsNotExist(e) {
			return fmt.Errorf("LEGACY_RECEIPT_REMOVAL_UNVERIFIED")
		}
		if e := retireLegacyIsolationMetadata(dir); e != nil {
			return e
		}
		return markMigrationComplete(dir)
	})
}
func restoreLegacyAMDSOriginal(r networkOnlyReceipt) error {
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService("Apple Mobile Device Service")
	if e != nil {
		return e
	}
	defer s.Close()
	cfg, e := s.Config()
	if e != nil {
		return e
	}
	if cfg.StartType != networkOnlyServiceStartType(r.StartType) && cfg.StartType != r.StartType {
		return fmt.Errorf("LEGACY_AMDS_CONFIGURATION_CHANGED")
	}
	if cfg.StartType != r.StartType {
		cfg.StartType = r.StartType
		if e = s.UpdateConfig(cfg); e != nil {
			return e
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e = diagnosticServiceState(ctx, s, svc.State(r.ServiceState)); e != nil {
		return e
	}
	cfg, e = s.Config()
	state, se := s.Query()
	if e != nil || se != nil || cfg.StartType != r.StartType || uint32(state.State) != r.ServiceState {
		return fmt.Errorf("LEGACY_AMDS_ORIGINAL_READBACK_FAILED")
	}
	return nil
}
func retireLegacyIsolationMetadata(dir string) error {
	originals, e := readPortableOriginalStore(dir)
	if e != nil || len(originals.Records) != 0 {
		return fmt.Errorf("LEGACY_PORTABLE_ORIGINALS_STILL_PENDING")
	}
	if _, e := readPortableProtectedFile(filepath.Join(dir, portablePropertyOriginalFile), portablePropertyStoreLimit); e == nil {
		if e = os.Remove(filepath.Join(dir, portablePropertyOriginalFile)); e != nil {
			return e
		}
		if _, e = readPortableProtectedFile(filepath.Join(dir, portablePropertyOriginalFile), portablePropertyStoreLimit); !os.IsNotExist(e) {
			return fmt.Errorf("LEGACY_EMPTY_PROPERTY_STORE_REMOVAL_UNVERIFIED")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	// Validate each fixed file before removal. Never remove unknown/malformed
	// records, and retain the separate property-restore audit as historical proof.
	if _, e := readUnpairedProductOwner(dir); e == nil {
		if e = os.Remove(filepath.Join(dir, unpairedProductOwnerFile)); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if _, e := readOwnedUnpairedProductChoice(dir); e == nil {
		if e = os.Remove(filepath.Join(dir, "network-only-choice.json")); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	return nil
}

// Fresh actual consent remains in main. This binds only U1 features to the
// current USB attachment, with no Apple session, pairing metadata or policy owner.
func PrepareSimplifiedIPadNetworkAfterConsent() error {
	if !SimplifiedIPadNetworkConfigured() || !NetworkOnlyCanConnect() {
		return fmt.Errorf("SIMPLIFIED_NETWORK_MIGRATION_UNRESOLVED")
	}
	ctx := connectionContext()
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("SIMPLIFIED_NETWORK_CONSENT_CONTEXT_UNPROVEN")
	}
	before := Inspect()
	if !networkOnlyUSBEligible(before) {
		return fmt.Errorf("SIMPLIFIED_NETWORK_FRESH_USB_UNPROVEN")
	}
	official, native := networkOnlyDriverRootHealthy(before, exactIPadRoot(before))
	if !official || !native {
		return fmt.Errorf("SIMPLIFIED_NETWORK_OFFICIAL_ROOT_UNPROVEN")
	}
	if e := verifyInstalledAppleControlDriver(); e != nil {
		return fmt.Errorf("DRIVER_HASH_NOT_EXPECTED_OR_UNREADABLE")
	}
	after := Inspect()
	if !descriptorAttachment(before).same(descriptorAttachment(after)) || ctx.Err() != nil {
		return fmt.Errorf("SIMPLIFIED_NETWORK_TARGET_CHANGED")
	}
	simplifiedNetworkFeatures.Store(true)
	return nil
}

func ClearSimplifiedIPadConnectionScope() { simplifiedNetworkFeatures.Store(false) }

type SimplifiedIPadNetworkStatus struct {
	Configured                    bool   `json:"simplified_network"`
	LegacySystemOriginalsVerified bool   `json:"legacy_system_originals_verified"`
	LegacyMigrationPending        bool   `json:"legacy_isolation_migration_pending"`
	Status                        string `json:"status"`
	Problem                       string `json:"problem,omitempty"`
	Notice                        string `json:"notice"`
	GatewaySyncDenied             bool   `json:"gateway_sync_restriction_required"`
	SharedServerAddress           string `json:"shared_server_address"`
	GroupingReadbackWarning       string `json:"grouping_readback_warning,omitempty"`
}

// Cached scalars only; UI refresh performs no descriptor or file scan.
func SimplifiedIPadNetworkSnapshot() SimplifiedIPadNetworkStatus {
	networkOnly.Lock()
	defer networkOnly.Unlock()
	warning, _ := simplifiedGroupingWarning.Load().(string)
	return SimplifiedIPadNetworkStatus{Configured: SimplifiedIPadNetworkConfigured(), LegacySystemOriginalsVerified: legacySystemOriginalsVerified.Load(), LegacyMigrationPending: networkOnly.status == "LEGACY_ISOLATION_MIGRATION_PENDING" || networkOnly.status == "LEGACY_METADATA_CLEANUP_PENDING", Status: networkOnly.status, Problem: migrationProblemCode(), Notice: networkOnly.notice, GatewaySyncDenied: true, SharedServerAddress: "10.6.9.1", GroupingReadbackWarning: warning}

}
