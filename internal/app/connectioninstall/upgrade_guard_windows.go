//go:build windows && amd64

package connectioninstall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
	"sync/atomic"
	"time"
)

const upgradeGuardEnv = "USB_LINK_UPGRADE_GUARD_V1"

type upgradeGuardState struct {
	enabled               atomic.Bool
	generation            uint64
	timer                 *time.Timer
	release               func()
	jobID                 string
	committed             bool
	reservationGeneration uint64
	startupRecorded       atomic.Bool
	startupNormal         atomic.Bool
	workerPID             uint32
	workerCreation        uint64
	workerExecutable      string
	recoveryWatching      bool
	retry                 *guardStorageRetry
	launchAttempted       bool
	retrySnapshot         atomic.Pointer[guardRetrySnapshot]
	launchUnknown         atomic.Pointer[guardRetrySnapshot]
	ownedJob              *UpdateJob
}

var activeUpgradeManager atomic.Pointer[RemoteManager]

func (m *RemoteManager) guardEnabled() bool {
	return coreUpgradeRequired() || m.upgradeGuard.enabled.Load()
}
func (m *RemoteManager) guardSet(seconds int) error {
	if coreUpgradeRequired() && seconds == 0 {
		return fmt.Errorf("CORE_UPGRADE_GUARD_REQUIRED")
	}
	m.mu.Lock()
	canRenewRetry := seconds == 900 && m.upgradeGuard.retry != nil && !m.upgradeGuard.committed && !m.upgradeGuard.launchAttempted
	if m.closing.Load() || m.requested.Load() || m.upgradeGuard.release != nil && !canRenewRetry {
		m.mu.Unlock()
		return fmt.Errorf("upgrade ownership active or closing")
	}
	m.upgradeGuard.generation++
	g := m.upgradeGuard.generation
	if m.upgradeGuard.timer != nil {
		m.upgradeGuard.timer.Stop()
	}
	m.upgradeGuard.enabled.Store(seconds > 0)
	if seconds > 0 && !coreUpgradeRequired() {
		m.upgradeGuard.timer = time.AfterFunc(time.Duration(seconds)*time.Second, func() {
			m.mu.Lock()
			if m.upgradeGuard.generation != g {
				m.mu.Unlock()
				return
			}
			m.upgradeGuard.enabled.Store(false)
			if m.upgradeGuard.committed {
				m.mu.Unlock()
				return
			} // Worker/cleanup owns the process, not the lease.
			id, api, recovery := m.upgradeGuard.jobID, m.api, m.recoveryAPI
			m.mu.Unlock()
			if id != "" {
				if err := m.cancelGuardJob(id, "Experiment expired before worker handoff"); err != nil {
					// Launch may win between the timer unlock and cancellation.
					// Preserve the executing API barrier unless the same live owner
					// is still positively idle under the manager lock.
					m.holdIdleGuardAPIs(id, err, api, recovery)
					return
				}
			}
			if api != nil && id != "" {
				api.ResetOwned(id)
			}
			if recovery != nil && id != "" {
				recovery.ResetOwned(id)
			}
		})
	}
	startRecoveryWatch := seconds > 0 && m.recoveryOnly && !m.upgradeGuard.recoveryWatching
	if startRecoveryWatch {
		m.upgradeGuard.recoveryWatching = true
	}
	m.mu.Unlock()
	if startRecoveryWatch {
		go m.watchRecoveryGuard()
	}
	return nil
}

// The cancellation callback runs outside m.mu. Recheck positive launch state
// while holding m.mu before changing any API applying barrier.
func (m *RemoteManager) holdIdleGuardAPIs(id string, err error, apis ...*remoteupdate.Server) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !remoteupdate.IsRetainedJobError(err) || m.upgradeGuard.jobID != id || m.upgradeGuard.release == nil || m.upgradeGuard.launchAttempted || m.upgradeGuard.committed {
		return
	}
	for _, api := range apis {
		if api != nil {
			api.HoldOwned(id)
		}
	}
}

func (m *RemoteManager) guardReserve() (uint64, error) {
	if !m.guardEnabled() {
		return 0, fmt.Errorf("guard lease expired before reservation")
	}
	release, err := acquireIPadUpgradeAdmission()
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.guardEnabled() || m.closing.Load() || m.upgradeGuard.release != nil {
		release()
		return 0, fmt.Errorf("maintenance experiment changed or reservation busy")
	}
	m.upgradeGuard.reservationGeneration++
	m.upgradeGuard.release = release
	return m.upgradeGuard.reservationGeneration, nil
}
func (m *RemoteManager) guardReleaseGeneration(g uint64) {
	m.mu.Lock()
	if g != 0 && m.upgradeGuard.reservationGeneration != g {
		m.mu.Unlock()
		return
	}
	release := m.upgradeGuard.release
	if retry := m.upgradeGuard.retrySnapshot.Load(); retry != nil && m.lastError == retry.detail {
		m.lastError = ""
	}
	m.upgradeGuard.release = nil
	m.upgradeGuard.jobID = ""
	m.upgradeGuard.committed = false
	m.upgradeGuard.workerPID = 0
	m.upgradeGuard.workerCreation = 0
	m.upgradeGuard.workerExecutable = ""
	m.upgradeGuard.retry = nil
	m.upgradeGuard.ownedJob = nil
	m.upgradeGuard.retrySnapshot.Store(nil)
	m.upgradeGuard.launchUnknown.Store(nil)
	m.upgradeGuard.launchAttempted = false
	m.mu.Unlock()
	if release != nil {
		release()
	}
}
func (m *RemoteManager) guardRelease() { m.guardReleaseGeneration(0) }
func (m *RemoteManager) guardReleaseJob(id string) {
	m.mu.Lock()
	g := m.upgradeGuard.reservationGeneration
	matches := m.upgradeGuard.jobID == id
	m.mu.Unlock()
	if matches {
		m.guardReleaseGeneration(g)
	}
}
func (m *RemoteManager) cancelGuardJob(id, detail string) error {
	m.mu.Lock()
	err := m.retryGuardTerminationLocked(id, detail)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	m.guardReleaseJob(id)
	return nil
}
func (m *RemoteManager) guardAPI(api *remoteupdate.Server) {
	api.Resilient = m.guardEnabled
	api.PersistenceRecovery = http.HandlerFunc(m.guardPerformance)
	api.Cancel = func(id string) error {
		return m.cancelGuardJob(id, "Explicitly cancelled before apply; signed bytes retained")
	}
	// These construction sites hold m.mu. Rebind only this live manager's
	// retained slot; a read of an old guarded job never confers ownership.
	if m.upgradeGuard.release != nil && m.upgradeGuard.jobID != "" {
		api.ResumeOwned(m.upgradeGuard.jobID, !m.upgradeGuard.launchAttempted && !m.upgradeGuard.committed)
	}
}
func upgradeGuardInherited() bool {
	return coreUpgradeRequired() || coreUpgradeGuard.Load() || os.Getenv(upgradeGuardEnv) == "1"
}
func inheritUpgradeGuard(c *exec.Cmd, enabled bool) {
	env := os.Environ()
	out := env[:0]
	for _, v := range env {
		if !strings.HasPrefix(v, upgradeGuardEnv+"=") {
			out = append(out, v)
		}
	}
	if enabled {
		out = append(out, upgradeGuardEnv+"=1")
	}
	c.Env = out
}
func recoveryUSBState(status string) string {
	switch status {
	case "USB_RECOVERY_WAITING", "USB_RECOVERY_MAINTENANCE":
		return "recovery_required"
	case "MAC_RUNNING", "APPLICATION_RUNNING", "TRIAL_RUNNING":
		return "monitoring"
	}
	return "unverified"
}

// A verified startup recovery ack proves deployment only, never normal network
// readiness. It is written only by the signed, owned --remote-install process.
func (m *RemoteManager) guardStartupRecoveryAck(status string) {
	if m.upgradeGuard.startupRecorded.Load() || !m.guardEnabled() || (!m.recoveryOnly && (remoteUSBHealthy() || recoveryUSBState(status) != "recovery_required")) || startupAckJobID() == "" {
		return
	}
	id := startupAckJobID()
	if ValidateRemoteLaunch(id, m.version) != nil {
		return
	}
	j, e := validatedJob(id, "")
	if e != nil || verifyCoreCandidateJob(j) != nil {
		return
	}
	if writeRemote(filepath.Join(m.root, "ready.json"), map[string]string{"id": id, "version": m.version, "usb_state": "recovery_required", "pid": fmt.Sprint(os.Getpid())}) == nil {
		m.upgradeGuard.startupRecorded.Store(true)
	}
}

// Recovery transport exposes only these three fixed experiment controls; its
// signed update/authentication handler still gates every request.
func (m *RemoteManager) guardPerformance(w http.ResponseWriter, r *http.Request) {
	q, err := remoteupdate.DecodeGuardControl(http.MaxBytesReader(w, r.Body, 512), r.URL.RawQuery)
	if err != nil || validMeasurement(q.Kind, q.Seconds, q.Nonce) != nil {
		http.Error(w, "fixed upgrade guard control required", 400)
		return
	}
	m.upgradeGuardMeasurement(w, r, q.Kind, q.Seconds, q.Nonce)
}
func (m *RemoteManager) upgradeGuardMeasurement(w http.ResponseWriter, r *http.Request, kind string, seconds int, id string) {
	m.mu.Lock()
	allowed := m.config.Enabled && !m.closing.Load() && !m.requested.Load() && (m.rawUSB.Load() || m.usbGUID() != "")
	m.mu.Unlock()
	if !allowed {
		http.Error(w, "authorized USB maintenance required", 403)
		return
	}
	if kind != "UPGRADEGUARDSTATE" {
		n := 0
		if kind == "UPGRADEGUARDON" {
			n = 900
		}
		if err := m.guardSet(n); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
	}
	m.mu.Lock()
	data, err := json.Marshal(map[string]any{"enabled": m.guardEnabled(), "reserved": m.upgradeGuard.release != nil, "worker_handoff_committed": m.upgradeGuard.committed, "maximum_seconds": 900, "default_enabled": coreUpgradeRequired(), "service_guard_required": coreUpgradeRequired(), "persistence_retry": m.upgradeGuard.retry != nil, "retry_job_id": m.upgradeGuard.jobID, "worker_launch_attempted": m.upgradeGuard.launchAttempted})
	m.mu.Unlock()
	if err != nil {
		http.Error(w, "guard state encoding failed", 500)
		return
	}
	sum := sha256.Sum256(data)
	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprintf(w, "DONE %s %d %s\n", id, len(data), hex.EncodeToString(sum[:]))
	w.Write(data)
}

func resetUpdateAPI(api *remoteupdate.Server, j UpdateJob) {
	if j.Guarded {
		api.ResetOwned(j.ID)
	} else {
		api.Reset()
	}
}

// Only a normal readiness acknowledgement already issued by main's 30-second
// gate may be refreshed. A newly constructed TLS manager cannot start it.
func (m *RemoteManager) guardRefreshNormalAck() {
	if !m.upgradeGuard.startupNormal.Load() || startupAckJobID() == "" {
		return
	}
	var j UpdateJob
	if readRemote(filepath.Join(m.root, "job.json"), &j) != nil || j.ID != startupAckJobID() || j.Status != "starting" {
		m.upgradeGuard.startupNormal.Store(false)
		return
	}
	if ValidateRemoteLaunch(j.ID, m.version) != nil || verifyCoreCandidateJob(j) != nil {
		return
	}
	state := "recovery_required"
	if !m.recoveryOnly && remoteUSBHealthy() {
		state = "verified"
	}
	_ = writeRemote(filepath.Join(m.root, "ready.json"), map[string]string{"id": j.ID, "version": m.version, "usb_state": state, "pid": fmt.Sprint(os.Getpid()), "observed_at_unix_nano": fmt.Sprint(time.Now().UnixNano())})
}

// A worker that finished with an explicit failure no longer owns settings.
// We retain its durable error/bytes, reset only its API slot and never release
// while its exact process or a timed-out candidate remains active/unknown.

func (m *RemoteManager) reconcileGuardFailure() {
	m.mu.Lock()
	id, g, committed := m.upgradeGuard.jobID, m.upgradeGuard.reservationGeneration, m.upgradeGuard.committed
	worker := UpdateJob{OwnerPID: m.upgradeGuard.workerPID, OwnerCreation: m.upgradeGuard.workerCreation, OwnerExecutable: m.upgradeGuard.workerExecutable}
	m.mu.Unlock()
	if id == "" || !committed {
		return
	}
	known, alive, err := recordedOwner(worker)
	if err != nil || !known || alive {
		return
	}
	var j UpdateJob
	if readRemote(filepath.Join(m.root, "job.json"), &j) != nil || j.ID != id {
		return
	}
	switch j.Status {
	case "failed", "declined", "cancelled", "interrupted", "manual_recovery_required", "handoff", "starting", "rollback":
	default:
		return
	}
	if j.CandidatePID != 0 {
		child := j
		child.OwnerPID = j.CandidatePID
		child.OwnerCreation = j.CandidateCreation
		child.OwnerExecutable = j.CandidateExecutable
		known, alive, err = recordedOwner(child)
		if err != nil || !known || alive {
			return
		}
	} else if j.Status == "manual_recovery_required" || j.Status == "starting" {
		return
	}
	if remoteupdate.UpdateInFlight(j.Status) {
		var err error
		selfCreation, creationErr := processCreation(uint32(os.Getpid()))
		self, selfErr := os.Executable()
		if creationErr == nil && selfErr == nil && remoteupdate.OrdinaryWriterAllowed(jobIdentity(j), uint32(os.Getpid()), selfCreation, strings.ToLower(self)) {
			j.Status, j.Detail = "failed", "Exact worker exited before handoff; current verified process retained"
			err = persistUpdateJob(m.root, j)
		} else {
			err = interruptDeadUpgradeJob(m.root, j, "Exact worker exited without completing update; old process retained, signed bytes and recovery records preserved")
		}
		if err != nil {
			return
		}
	}
	m.mu.Lock()
	if m.upgradeGuard.jobID != id || m.upgradeGuard.reservationGeneration != g {
		m.mu.Unlock()
		return
	}
	m.upgradeGuard.committed = false
	m.requested.Store(false)
	api, recovery := m.api, m.recoveryAPI
	m.mu.Unlock()
	m.guardReleaseGeneration(g)
	if api != nil {
		api.ResetOwned(id)
	}
	if recovery != nil {
		recovery.ResetOwned(id)
	}
}

// Recovery managers do not run the normal adapter/listener watcher. Start a
// bounded record-only observer only while this experiment or handoff owns it.
func (m *RemoteManager) watchRecoveryGuard() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-m.done:
			m.mu.Lock()
			m.upgradeGuard.recoveryWatching = false
			m.mu.Unlock()
			return
		case <-tick.C:
			m.reconcileGuardFailure()
			m.mu.Lock()
			if !m.guardEnabled() && !m.upgradeGuard.committed {
				m.upgradeGuard.recoveryWatching = false
				m.mu.Unlock()
				return
			}
			m.mu.Unlock()
		}
	}
}
