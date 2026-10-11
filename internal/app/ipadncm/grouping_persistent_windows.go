//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"io"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/diagnostics/grouptrial"
)

func configuredGroupingPath(dir, root string) string {
	h := sha256.Sum256([]byte(strings.ToUpper(root)))
	return filepath.Join(dir, "network-grouping-"+hex.EncodeToString(h[:])+".json")
}

func readConfiguredGrouping(path string) (groupingJournal, error) {
	var j groupingJournal
	b, e := readAMDSDiagnosticReceipt(path)
	if e != nil {
		return j, e
	}
	if len(b) > 1024 {
		return j, fmt.Errorf("grouping receipt too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&j) != nil || !validJournal(j) {
		return j, fmt.Errorf("invalid grouping receipt")
	}
	var tail any
	if d.Decode(&tail) != io.EOF || filepath.Base(path) != filepath.Base(configuredGroupingPath(filepath.Dir(path), j.RootID)) {
		return j, fmt.Errorf("grouping receipt path or trailing data invalid")
	}
	return j, nil
}

// The pending file already owns an exact original-value restoration obligation.
// The network connection retains that obligation, never adopting an unknown layout or granting
// fresh USB authority from a saved file. All networking still needs live consent.
func readOwnedPendingNetworkGrouping(dir string) (j groupingJournal, found bool, err error) {
	if !networkOnlyDriverStoreProtected(dir) {
		return j, false, fmt.Errorf("PRODUCT_GROUPING_STORE_UNPROVEN")
	}
	b, e := readProtectedNetworkOnlyFile(journalPath(dir), 1024)
	if os.IsNotExist(e) {
		return j, false, nil
	}
	found = true
	if e != nil {
		return j, true, fmt.Errorf("PRODUCT_GROUPING_PENDING_UNREADABLE")
	}
	j, e = decodeGroupingJournal(b)
	if e != nil {
		return j, true, e
	}
	k, problem := groupingOwnedKey(j, registry.QUERY_VALUE)
	if problem != "" {
		return j, true, fmt.Errorf("%s", problem)
	}
	defer k.Close()
	value, _, e := k.GetBinaryValue("EnumeratorClass")
	if e != nil || !bytes.Equal(value, groupingBytes) {
		return j, true, fmt.Errorf("PRODUCT_GROUPING_PENDING_VALUE_NOT_OWNED")
	}
	// Two possible backups or a changed protected record are not equivalent.
	_, ce := readConfiguredGrouping(configuredGroupingPath(dir, j.RootID))
	if !os.IsNotExist(ce) {
		return j, true, fmt.Errorf("PRODUCT_GROUPING_PENDING_CONFIGURATION_AMBIGUOUS")
	}
	fresh, e := readProtectedNetworkOnlyFile(journalPath(dir), 1024)
	if e != nil || !bytes.Equal(b, fresh) {
		return j, true, fmt.Errorf("PRODUCT_GROUPING_PENDING_CHANGED_DURING_READ")
	}
	return j, true, nil
}

func readStartupOwnedGrouping(dir, root string) (j groupingJournal, pending bool, err error) {
	j, err = readConfiguredGrouping(configuredGroupingPath(dir, root))
	if !os.IsNotExist(err) {
		return j, false, err
	}
	if !SimplifiedIPadNetworkConfigured() {
		return j, false, err
	}
	j, found, e := readOwnedPendingNetworkGrouping(dir)
	if e != nil {
		return j, true, e
	}
	if !found {
		return j, false, err
	}
	if !strings.EqualFold(j.RootID, root) {
		return j, true, fmt.Errorf("PRODUCT_GROUPING_PENDING_ON_DIFFERENT_ROOT")
	}
	return j, true, nil
}

func (b *groupingBackend) commitConfiguration() string {
	if !b.result.GroupingObserved || b.result.NativeStartedNodes == 0 || b.applicationRestoreError != "" {
		return "PERSISTENT_GROUPING_OBSERVATION_OR_CLEANUP_UNCONFIRMED"
	}
	k, e := recoveryKey(b.j)
	if e != "" {
		return e
	}
	defer k.Close()
	v, _, er := k.GetBinaryValue("EnumeratorClass")
	if er != nil || !bytes.Equal(v, groupingBytes) {
		return "PERSISTENT_GROUPING_READBACK_FAILED"
	}
	from, _ := windows.UTF16PtrFromString(journalPath(b.dir))
	to, _ := windows.UTF16PtrFromString(configuredGroupingPath(b.dir, b.j.RootID))
	// Never replace another configuration receipt or remove the sole backup.
	if er = windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); er != nil {
		return "PERSISTENT_GROUPING_COMMIT_FAILED"
	}
	return ""
}

// U1 features come from an accepted diagnostic stage or the fresh consented
// product owner. A saved grouping record never grants live USB permission.
func RunPersistentGrouping(version, dir, system string, mode Result, consent func() bool, activate func(Result) (Result, string), applicationConsent func() bool) (r GroupingResult) {
	b := &groupingBackend{version: version, dir: dir, system: system, mode: mode, result: &r, activate: activate, applicationConsent: applicationConsent, eventStartup: IPadCandidateFeatures().EventStartup}
	r.Transaction = grouptrial.RunPersistent(b, consent, b.commitConfiguration)
	r.AfterRestore = Inspect()
	return
}

func RunConfiguredGrouping(version, dir, system string, mode Result, applicationConsent func() bool) (r GroupingResult, found bool) {
	root := exactIPadRoot(mode.Before)
	if root == "" {
		return r, false
	}
	j, pending, e := readStartupOwnedGrouping(dir, root)
	if os.IsNotExist(e) {
		return r, false
	}
	found = true
	if e != nil || !strings.EqualFold(j.RootID, root) {
		r.Transaction.Error = "CONFIGURED_GROUPING_RECEIPT_INVALID"
		return
	}
	k, err := recoveryKey(j)
	if err != "" {
		r.Transaction.Error = err
		return
	}
	v, _, e := k.GetBinaryValue("EnumeratorClass")
	k.Close()
	if e != nil || !bytes.Equal(v, groupingBytes) {
		r.Transaction.Error = "CONFIGURED_GROUPING_CHANGED"
		return
	}
	b := &groupingBackend{version: version, dir: dir, system: system, mode: mode, j: j, result: &r, applicationConsent: applicationConsent, eventStartup: IPadCandidateFeatures().EventStartup}
	r.Before = mode.Before
	r.Transaction = grouptrial.Report{Status: "CONFIGURATION_REUSED_NO_WRITE_OR_RESTART", ConfigurationRetained: true, BackupSaved: true}
	if pending {
		r.Transaction.Status = "OWNED_PRODUCT_PENDING_CONFIGURATION_REUSED_NO_WRITE_OR_RESTART"
	}
	r.Transaction.Observation = b.Observe()
	if b.applicationRestoreError != "" {
		r.Transaction.Error = b.applicationRestoreError
		r.Transaction.RestoreError = b.applicationRestoreError
	}
	if pending && r.Transaction.Error == "" {
		if problem := b.commitConfiguration(); problem != "" {
			r.Transaction.Error = problem
			r.Transaction.Status = "OWNED_PRODUCT_PENDING_COMMIT_UNCONFIRMED_RETAINED"
		}
	}
	return
}

func RestoreConfiguredGroupings(dir, system string) string {
	entries, e := os.ReadDir(dir)
	if e != nil {
		return "CONFIGURED_GROUPING_RECEIPTS_UNAVAILABLE"
	}
	count := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "network-grouping-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		count++
		if count > 32 {
			return "CONFIGURED_GROUPING_RECEIPT_LIMIT"
		}
		path := filepath.Join(dir, name)
		j, e := readConfiguredGrouping(path)
		if e != nil {
			return "CONFIGURED_GROUPING_RECEIPT_INVALID"
		}
		r := restoreGrouping(dir, system, j)
		if r.Error != "" {
			return r.Error
		}
		if os.Remove(path) != nil {
			return "CONFIGURED_GROUPING_RECEIPT_REMOVE_FAILED"
		}
	}
	return ""
}

// Startup is a bounded, read-only inspection. A malformed or foreign pending
// record is retained as an iPad warning, never restored/restarted automatically.
func InspectPersistentNetworkGrouping(dir string) (r GroupingRecovery) {
	_, found, e := readOwnedPendingNetworkGrouping(dir)
	r.Pending, r.ConfigurationPreserved = found, found && e == nil
	if e != nil {
		r.Error = e.Error()
		return
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		r.Error = "NETWORK_GROUPING_STORE_UNREADABLE"
		return
	}
	count := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "network-grouping-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		count++
		if count > 32 {
			r.Error = "NETWORK_GROUPING_RECEIPT_LIMIT"
			return
		}
		j, e := readConfiguredGrouping(filepath.Join(dir, name))
		if e != nil {
			r.Error = "NETWORK_GROUPING_RECEIPT_INVALID"
			return
		}
		k, problem := groupingOwnedKey(j, registry.QUERY_VALUE)
		if problem != "" {
			r.Error = problem
			return
		}
		value, _, e := k.GetBinaryValue("EnumeratorClass")
		k.Close()
		if e != nil || !bytes.Equal(value, groupingBytes) {
			r.Error = "NETWORK_GROUPING_READBACK_CHANGED"
			return
		}
	}
	return
}

// Explicit confirmed uninstall only. Preflight every protected original before
// any mutation; normal startup/upgrade never calls this restore entry point.
func RestorePersistentNetworkGrouping(dir, system string) string {
	if !networkOnlyDriverStoreProtected(dir) {
		return "NETWORK_GROUPING_STORE_UNPROVEN"
	}
	pending, pe := readProtectedNetworkOnlyFile(journalPath(dir), 1024)
	var pendingJournal groupingJournal
	if pe == nil {
		var e error
		pendingJournal, e = decodeGroupingJournal(pending)
		if e != nil {
			return e.Error()
		}
	} else if !os.IsNotExist(pe) {
		return "NETWORK_GROUPING_PENDING_UNREADABLE"
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return "NETWORK_GROUPING_STORE_UNREADABLE"
	}
	journals := []groupingJournal{}
	if pe == nil {
		journals = append(journals, pendingJournal)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "network-grouping-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		if len(journals) >= 33 {
			return "NETWORK_GROUPING_RECEIPT_LIMIT"
		}
		j, e := readConfiguredGrouping(filepath.Join(dir, name))
		if e != nil {
			return "NETWORK_GROUPING_RECEIPT_INVALID"
		}
		if pe == nil && strings.EqualFold(j.RootID, pendingJournal.RootID) {
			return "NETWORK_GROUPING_DUPLICATE_ORIGINALS"
		}
		journals = append(journals, j)
	}
	for _, j := range journals {
		k, problem := groupingOwnedKey(j, registry.QUERY_VALUE)
		if problem != "" {
			return problem
		}
		v, _, e := k.GetBinaryValue("EnumeratorClass")
		k.Close()
		if e != registry.ErrNotExist && (e != nil || !bytes.Equal(v, groupingBytes)) {
			return "NETWORK_GROUPING_UNINSTALL_OWNERSHIP_CHANGED"
		}
	}
	if pe == nil {
		r := RecoverGrouping(dir, system)
		if r.Error != "" || !r.JournalCleared {
			if r.Error != "" {
				return r.Error
			}
			return "NETWORK_GROUPING_PENDING_RETAINED"
		}
	}
	return RestoreConfiguredGroupings(dir, system)
}
