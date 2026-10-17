//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

var localNCMDirectOperation sync.Mutex

func readLocalNCMDirectJournal(dir string) (localNCMDirectJournal, bool, error) {
	var j localNCMDirectJournal
	if !networkOnlyDriverStoreProtected(dir) {
		return j, false, errors.New("DIRECT_RECOVERY_STORE_UNPROVEN")
	}
	b, e := readPortableProtectedFile(filepath.Join(dir, localNCMDirectJournalName), localNCMDirectJournalLimit)
	if os.IsNotExist(e) {
		return j, false, nil
	}
	if e != nil {
		return j, false, errors.New("DIRECT_RECOVERY_RECORD_UNREADABLE")
	}
	j, e = decodeLocalNCMDirectJournal(b)
	return j, true, e
}
func sameDirectJournal(a, b localNCMDirectJournal) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func verifyDirectJournal(dir string, j localNCMDirectJournal) error {
	current, found, e := readLocalNCMDirectJournal(dir)
	if e != nil || !found || !sameDirectJournal(current, j) {
		return errors.New("DIRECT_RECOVERY_OWNERSHIP_CHANGED")
	}
	return nil
}
func saveLocalNCMDirectJournal(dir string, j localNCMDirectJournal, previous *localNCMDirectJournal) error {
	if !j.valid() {
		return errors.New("DIRECT_RECOVERY_RECORD_INVALID")
	}
	current, found, e := readLocalNCMDirectJournal(dir)
	if e != nil {
		return e
	}
	if previous == nil && found || previous != nil && (!found || !sameDirectJournal(current, *previous)) {
		return errors.New("DIRECT_RECOVERY_ALREADY_PENDING")
	}
	b, e := json.Marshal(j)
	if e != nil || len(b) > localNCMDirectJournalLimit {
		return errors.New("DIRECT_RECOVERY_RECORD_INVALID")
	}
	f, temp, e := createPortableProtectedTemp(dir)
	if e != nil {
		return errors.New("DIRECT_RECOVERY_WRITE_FAILED")
	}
	defer os.Remove(temp)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return errors.New("DIRECT_RECOVERY_WRITE_FAILED")
	}
	rb, e := readPortableProtectedFile(temp, localNCMDirectJournalLimit)
	if e != nil || !bytes.Equal(rb, b) {
		return errors.New("DIRECT_RECOVERY_READBACK_FAILED")
	}
	if !networkOnlyDriverStoreProtected(dir) {
		return errors.New("DIRECT_RECOVERY_STORE_UNPROVEN")
	}
	if previous != nil {
		if e = verifyDirectJournal(dir, *previous); e != nil {
			return e
		}
	} else {
		_, found, e = readLocalNCMDirectJournal(dir)
		if e != nil || found {
			return errors.New("DIRECT_RECOVERY_ALREADY_PENDING")
		}
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if previous != nil {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if e = windows.MoveFileEx(windows.StringToUTF16Ptr(temp), windows.StringToUTF16Ptr(filepath.Join(dir, localNCMDirectJournalName)), flags); e != nil {
		return errors.New("DIRECT_RECOVERY_WRITE_FAILED")
	}
	return verifyDirectJournal(dir, j)
}
func clearLocalNCMDirectJournal(dir string, j localNCMDirectJournal) error {
	if e := verifyDirectJournal(dir, j); e != nil {
		return e
	}
	if e := os.Remove(filepath.Join(dir, localNCMDirectJournalName)); e != nil {
		return errors.New("DIRECT_RECOVERY_CLEAR_FAILED")
	}
	return nil
}
func directTargetMatches(j localNCMDirectJournal, s Snapshot) bool {
	if !j.valid() || s.Error != "" || s.ConnectionReadErrors != 0 || len(s.Devices) != 1 || !strings.EqualFold(exactIPadRoot(s), j.Root) {
		return false
	}
	d := s.Devices[0]
	return len(d.Errors) == 0 && d.USBDescriptorIdentityVerified && d.USBSerialSHA256 == j.SerialSHA256 && d.hub == j.Hub && d.port == j.Port && d.PID == "12AB"
}
func directOriginalLayout(j localNCMDirectJournal, s Snapshot) bool {
	return directTargetMatches(j, s) && networkOnlyUSBEligible(s) && s.Devices[0].CurrentConfiguration == j.OriginalConfiguration && directConfigurationDigest(s.Devices[0].Configurations, s.Devices[0].CurrentConfiguration) == j.OriginalConfigurationSHA256
}
func directOrdinaryFallback(j localNCMDirectJournal, s Snapshot) bool {
	return j.RequestedMode == 3 && directTargetMatches(j, s) && networkOnlyUSBEligible(s) && s.Devices[0].CurrentConfiguration == 5 && HasActiveNCM(s)
}
func restoreLocalNCMDirectLocked(dir string) error {
	j, found, e := readLocalNCMDirectJournal(dir)
	if e != nil || !found {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	s := inventory(ctx)
	if ctx.Err() != nil || (!directOriginalLayout(j, s) && !directOrdinaryFallback(j, s)) {
		return errors.New("DIRECT_REPLUG_REQUIRED")
	}
	return clearLocalNCMDirectJournal(dir, j)
}

// Public builds may verify recovery, but never send mode 5 or a speculative
// reset. Disappearance alone could be re-enumeration and does not clear intent.
func RestoreLocalNCMDirect(dir string) error {
	localNCMDirectOperation.Lock()
	defer localNCMDirectOperation.Unlock()
	return restoreLocalNCMDirectLocked(dir)
}
