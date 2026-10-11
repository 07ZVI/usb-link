//go:build windows && amd64

package connectioninstall

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
	"testing"
)

func TestGuardStorageRetentionNeverInfersUnlaunchedFromEmptyPID(t *testing.T) {
	for _, boundary := range []struct{ attempted, committed bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		id := strings.Repeat("a", 32)
		m := &RemoteManager{}
		m.upgradeGuard.jobID = id
		m.upgradeGuard.release = func() { t.Error("write failure released live owner") }
		m.upgradeGuard.launchAttempted, m.upgradeGuard.committed = boundary.attempted, boundary.committed
		// Deliberately no worker PID/creation: a missing receipt after native
		// creation/save failure must not grant the exact-id idle cancellation path.
		j := UpdateJob{ID: id, Guarded: true, Status: "handoff"}
		m.mu.Lock()
		err := m.retainGuardStorageLocked(nil, j, []string{"awaiting_auto_install", "handoff"}, "failed", "write failed", errors.New("disk full"))
		m.mu.Unlock()
		want := !boundary.attempted && !boundary.committed
		if remoteupdate.IsRetainedJobError(err) != want || (m.upgradeGuard.retry != nil) != want || m.upgradeGuard.release == nil {
			t.Fatalf("boundary=%+v was reclassified incorrectly", boundary)
		}
	}
}

// These exercise real manager error classification/API retention, without system
// writes. Windows execution is required; portable Server fixtures do not claim it.
func TestApplyFailurePreservesMemoryOwnerWhenStorageUnreadable(t *testing.T) {
	id := strings.Repeat("a", 32)
	m := &RemoteManager{root: t.TempDir()}
	m.upgradeGuard.jobID = id
	m.upgradeGuard.release = func() { t.Error("lost reservation") }
	m.upgradeGuard.ownedJob = &UpdateJob{ID: id, Guarded: true, Status: "staged"}
	m.closing.Store(true)
	api := &remoteupdate.Server{}
	api.ResumeOwned(id, false)
	err := m.apply(api, id)
	if !remoteupdate.IsRetainedJobError(err) || m.upgradeGuard.retry == nil || m.upgradeGuard.jobID != id {
		t.Fatal("apply failure discarded unreadable storage owner's slot", err)
	}
	if !api.ResetOwned(id) {
		t.Fatal("exact slot no longer available")
	}
	m.mu.Lock()
	err = m.retryGuardTerminationLocked(id, "retry")
	m.mu.Unlock()
	if !remoteupdate.IsRetainedJobError(err) || m.upgradeGuard.release == nil {
		t.Fatal("missing durable record allowed cancellation", err)
	}
}
func TestTimerCancellationCannotDowngradeLaunchWinner(t *testing.T) {
	id := strings.Repeat("a", 32)
	for _, retained := range []bool{false, true} {
		m := &RemoteManager{}
		m.upgradeGuard.jobID = id
		m.upgradeGuard.release = func() {}
		m.upgradeGuard.launchAttempted = true
		api := &remoteupdate.Server{Token: strings.Repeat("b", 64), Resilient: func() bool { return true }, Cancel: func(string) error { t.Fatal("launched worker exposed to cancellation"); return nil }}
		api.ResumeOwned(id, false)
		err := errors.New("launch won")
		if retained {
			err = remoteupdate.RetainJobError(err)
		}
		m.holdIdleGuardAPIs(id, err, api)
		req := httptest.NewRequest(http.MethodPost, "/v1/cancel", strings.NewReader(`{"id":"`+id+`"}`))
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("Authorization", "Bearer "+api.Token)
		out := httptest.NewRecorder()
		api.ServeHTTP(out, req)
		if out.Code != http.StatusConflict {
			t.Fatal("timer reclassified live launch as idle", out.Code)
		}
	}
}

func TestUnknownNativeLaunchReportsRecoveryEvenWhenStoreUnreadable(t *testing.T) {
	m := &RemoteManager{root: t.TempDir(), version: "0.8.76"}
	id := strings.Repeat("a", 32)
	m.upgradeGuard.launchUnknown.Store(&guardRetrySnapshot{id: id, version: "0.8.77", detail: "creation unconfirmed"})
	state := m.status().(map[string]string)
	if state["id"] != id || state["status"] != "manual_recovery_required" || state["deployment_state"] != "worker_creation_unconfirmed" {
		t.Fatal("unknown process misreported as idle/complete", state)
	}
}
