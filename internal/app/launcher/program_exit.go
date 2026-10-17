package launcher

import (
	"encoding/json"
	"fmt"
	"sync"
)

type programExitStatus struct {
	Phase          string `json:"phase"`
	ID             string `json:"request_id,omitempty"`
	Error          string `json:"error,omitempty"`
	Busy           bool   `json:"busy"`
	CloseFollowers bool   `json:"close_followers,omitempty"`
	UIDrained      bool   `json:"ui_drained,omitempty"`
}

// The application joins before restoration; the service stays alive until the
// owner UI has received the final reply. A failed restore can be retried.
type programExitOwner struct {
	SID          string
	Session, PID uint32
	Creation     uint64
}

func (o programExitOwner) valid() bool {
	return o.SID != "" && o.Session != 0 && o.PID != 0 && o.Creation != 0
}

type coreProgramExit struct {
	mu          sync.Mutex
	status      programExitStatus
	owner       programExitOwner
	stopOnce    sync.Once
	stopAndWait func()
	restore     func() error
	committed   chan struct{}
	commitOnce  sync.Once
	cached      json.RawMessage
	record      func(stage, id string)
	restart     bool
	uis         map[programExitOwner]*programLoginUI
}

func newCoreProgramExit(stop func(), restore func() error) *coreProgramExit {
	return &coreProgramExit{status: programExitStatus{Phase: "idle"}, stopAndWait: stop, restore: restore, committed: make(chan struct{})}
}
func validProgramExitID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func (e *coreProgramExit) snapshot() programExitStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.statusLocked()
}
func (e *coreProgramExit) statusLocked() programExitStatus {
	s := e.status
	if e.restart && s.Phase == "ready" {
		s.CloseFollowers = true
		s.UIDrained = e.uiDrainedLocked()
	}
	return s
}
func (e *coreProgramExit) evidence(stage, id string) {
	if e.record != nil {
		e.record(stage, id)
	}
}
func (e *coreProgramExit) active() bool { return e.snapshot().Phase != "idle" }
func (e *coreProgramExit) begin(id string, owner programExitOwner) error {
	return e.beginWithMode(id, owner, false)
}
func (e *coreProgramExit) beginWithMode(id string, owner programExitOwner, restart bool) error {
	if !validProgramExitID(id) || !owner.valid() {
		return fmt.Errorf("CORE_EXIT_REQUEST_INVALID")
	}
	e.mu.Lock()
	if e.owner.valid() && (e.owner.SID != owner.SID || e.owner.Session != owner.Session) {
		e.mu.Unlock()
		return fmt.Errorf("CORE_EXIT_OWNER_CHANGED")
	}
	if e.owner.valid() && e.owner != owner && (e.status.Phase != "failed" && e.status.Phase != "ready" || e.status.ID == id) {
		e.mu.Unlock()
		return fmt.Errorf("CORE_EXIT_OWNER_CHANGED")
	}
	if e.status.Phase != "idle" && e.status.Phase != "failed" && !(e.status.Phase == "ready" && e.status.ID != id) {
		same := e.status.ID == id
		e.mu.Unlock()
		if same {
			return nil
		}
		return fmt.Errorf("CORE_EXIT_IN_PROGRESS")
	}
	e.owner = owner
	e.restart = restart
	e.status = programExitStatus{Phase: "stopping_connections", ID: id, Busy: true}
	e.mu.Unlock()
	go func() {
		e.stopOnce.Do(e.stopAndWait)
		e.evidence("APPLICATION_JOINED", id)
		e.mu.Lock()
		e.status.Phase = "restoring"
		e.mu.Unlock()
		err := e.restore()
		e.mu.Lock()
		defer e.mu.Unlock()
		e.status.Busy = false
		if err != nil {
			e.status.Phase = "failed"
			e.status.Error = "CORE_EXIT_RECOVERY_PENDING"
			e.evidence("RESTORE_FAILED", id)
		} else {
			e.status.Phase = "ready"
			e.evidence("RESTORE_READY", id)
		}
	}()
	return nil
}
func (e *coreProgramExit) prepareCommit(id string, owner programExitOwner) (func(), error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !owner.valid() || e.owner != owner || id != e.status.ID || e.status.Phase != "ready" {
		return nil, fmt.Errorf("CORE_EXIT_NOT_READY_OR_OWNER_CHANGED")
	}
	if e.restart && !e.uiDrainedLocked() {
		return nil, fmt.Errorf("CORE_EXIT_UI_STILL_RUNNING")
	}
	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.owner == owner && e.status.ID == id && e.status.Phase == "ready" {
			e.commitOnce.Do(func() { e.status.Phase = "committed"; e.evidence("COMMIT_ACKNOWLEDGED", id); close(e.committed) })
		}
	}, nil
}
func (e *coreProgramExit) display(current json.RawMessage, isolation any, version string) json.RawMessage {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(current) > 0 {
		e.cached = append(e.cached[:0], current...)
	}
	var envelope map[string]any
	if json.Unmarshal(e.cached, &envelope) != nil || envelope == nil {
		envelope = map[string]any{}
	}
	desktop, _ := envelope["desktop"].(map[string]any)
	if desktop == nil {
		desktop = map[string]any{"event": "status", "version": version}
		envelope["desktop"] = desktop
	}
	desktop["program_exit"] = e.statusLocked()
	desktop["default_network_isolation"] = isolation
	if e.status.Phase != "idle" {
		desktop["stopping"] = false // Exit retry remains usable after a failed restore.
		desktop["devices"] = []any{}
		desktop["connected"] = false
		desktop["share_ready"] = false
		desktop["detail"] = "正在退出程序；連線資料已停止更新，恢復結果以目前退出狀態為準。"
		connectionStatus := "MONITOR_STOPPED"
		if e.status.Phase == "stopping_connections" {
			connectionStatus = "MONITOR_STOPPING"
		}
		envelope["connections"] = map[string]any{
			"Mac":  map[string]any{"device_kind": "Mac", "status": connectionStatus},
			"iPad": map[string]any{"device_kind": "iPad", "status": connectionStatus},
		}
		delete(envelope, "events")
	}
	b, _ := json.Marshal(envelope)
	return b
}
