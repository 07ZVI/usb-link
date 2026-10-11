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
func TestRemovedApplyCannotTouchRetainedOwner(t *testing.T) {
	id := strings.Repeat("a", 32)
	m := &RemoteManager{root: t.TempDir()}
	m.upgradeGuard.jobID = id
	m.upgradeGuard.release = func() { t.Error("lost local recovery reservation") }
	m.upgradeGuard.ownedJob = &UpdateJob{ID: id, Guarded: true, Status: "staged"}
	if err := m.apply(nil, id); err != errRemoteMaintenanceRemoved {
		t.Fatal(err)
	}
	if m.upgradeGuard.jobID != id || m.upgradeGuard.release == nil || m.upgradeGuard.retry != nil {
		t.Fatal("removed remote apply changed local recovery")
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
