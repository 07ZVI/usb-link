//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
)

type guardStorageRetry struct {
	job            UpdateJob
	allowed        []string
	status, detail string
}
type guardRetrySnapshot struct{ id, version, detail string }

// Called with m.mu held. Only a positively unlaunched owner may preserve a
// terminal transition for replay. Missing durable worker fields prove nothing.
func (m *RemoteManager) retainGuardStorageLocked(api *remoteupdate.Server, j UpdateJob, allowed []string, status, detail string, cause error) error {
	if !j.Guarded || m.upgradeGuard.jobID != j.ID || m.upgradeGuard.release == nil || m.upgradeGuard.committed || m.upgradeGuard.launchAttempted {
		return cause
	}
	m.upgradeGuard.retry = &guardStorageRetry{job: j, allowed: append([]string(nil), allowed...), status: status, detail: detail}
	m.lastError = "Guarded update persistence failed; exact idle job and reservation retained: " + cause.Error()
	m.upgradeGuard.retrySnapshot.Store(&guardRetrySnapshot{id: j.ID, version: j.Manifest.Version, detail: m.lastError})
	if api != nil {
		api.HoldOwned(j.ID)
	}
	return remoteupdate.RetainJobError(cause)
}

func sameStorageRetryJob(a, b UpdateJob) bool {
	a.Status, b.Status = "", ""
	a.Detail, b.Detail = "", ""
	a.UpdatedUTC, b.UpdatedUTC = "", ""
	return a == b
}

// Called under m.mu, outside the Server mutex. Every successful replay still
// uses the production cross-process mutex, actual-writer validation and CAS.
func (m *RemoteManager) retryGuardTerminationLocked(id, detail string) error {
	if id == "" || m.upgradeGuard.jobID != id || m.upgradeGuard.release == nil || m.upgradeGuard.committed || m.upgradeGuard.launchAttempted || m.requested.Load() {
		return fmt.Errorf("exact idle upgrade owner required; executing or unknown launch cannot be cancelled")
	}
	var j UpdateJob
	if err := readRemote(filepath.Join(m.root, "job.json"), &j); err != nil || j.ID != id {
		cause := fmt.Errorf("owned update unavailable; recovery remains reserved: %v", err)
		if m.upgradeGuard.retry == nil && m.upgradeGuard.ownedJob != nil {
			return m.retainGuardStorageLocked(nil, *m.upgradeGuard.ownedJob, []string{"staged", "awaiting_local_approval", "awaiting_auto_install", "cancelled"}, "cancelled", detail, cause)
		}
		return remoteupdate.RetainJobError(cause)
	}
	if !j.Guarded {
		return fmt.Errorf("guarded job required")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	creation, err := processCreation(uint32(os.Getpid()))
	if err != nil || !remoteupdate.OrdinaryWriterAllowed(jobIdentity(j), uint32(os.Getpid()), creation, strings.ToLower(self)) || Verify(self) != nil {
		return fmt.Errorf("actual process no longer owns idle job")
	}
	status := "cancelled"
	if m.upgradeGuard.ownedJob == nil {
		return fmt.Errorf("verified in-memory idle owner unavailable")
	}
	if !sameStorageRetryJob(j, *m.upgradeGuard.ownedJob) {
		return fmt.Errorf("retained idle job content changed")
	}
	allowed := []string{"staged", "awaiting_local_approval", "awaiting_auto_install"}
	if retry := m.upgradeGuard.retry; retry != nil {
		if !sameStorageRetryJob(j, retry.job) {
			return fmt.Errorf("persistence retry job identity/content changed")
		}
		allowed, status, detail = retry.allowed, retry.status, retry.detail
	}
	if !remoteupdate.IdleTerminationRetryAllowed(jobIdentity(j), jobIdentity(*m.upgradeGuard.ownedJob), allowed, m.upgradeGuard.launchAttempted, m.upgradeGuard.committed) {
		return fmt.Errorf("update is not this owner's retained idle transition")
	}
	expected := jobIdentity(j)
	next := j
	next.Status, next.Detail = status, detail
	if err := writeJobOwned(m.root, next, &expected, false); err != nil {
		return m.retainGuardStorageLocked(nil, j, append(allowed, status), status, detail, err)
	}
	return nil
}
