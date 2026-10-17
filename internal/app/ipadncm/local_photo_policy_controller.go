//go:build usblink_local_remote

package ipadncm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

type photoPolicyScan struct {
	Nodes              []portableNodeReceipt
	Present, Unhealthy int
	RestartRequired    bool
}
type photoPolicyBackend interface {
	photoPolicyStore
	lock() (func(), error)
	supported() error
	scan(string) (photoPolicyScan, error)
}
type localPhotoPolicyStatus struct {
	Available                    bool   `json:"available"`
	Requested                    bool   `json:"requested"`
	Effective                    bool   `json:"effective"`
	Busy                         bool   `json:"busy"`
	Persistence                  string `json:"persistence"`
	SavedEnabled                 bool   `json:"saved_enabled"`
	RequestID                    string `json:"request_id"`
	RejectedID                   string `json:"rejected_id,omitempty"`
	RejectedError                string `json:"rejected_error,omitempty"`
	Phase                        string `json:"phase"`
	Error                        string `json:"error,omitempty"`
	CauseCode                    string `json:"cause_code,omitempty"`
	NativeKind                   string `json:"native_kind,omitempty"`
	NativeCode                   uint32 `json:"native_code,omitempty"`
	PolicyArmed                  bool   `json:"policy_armed"`
	RestartRequired              bool   `json:"restart_required"`
	RestoreRequiresReenumeration bool   `json:"restore_requires_reenumeration"`
	RetainedOnExit               bool   `json:"retained_on_exit"`
	OwnedNodes                   int    `json:"owned_nodes"`
	ObservedNodes                int    `json:"observed_nodes"`
	PresentNodes                 int    `json:"present_nodes"`
	UnhealthyNodes               int    `json:"unhealthy_nodes"`
}

func classicPhotoPolicyStateClear(s localPhotoStatus) bool {
	return !s.Requested && !s.SavedEnabled && !s.Effective && !s.Busy && s.OwnedNodes == 0 && s.Phase != "recovery_pending" && s.Phase != "recovering" && s.Error == ""
}

type localPhotoPolicyController struct {
	mu                                                                 sync.Mutex
	operation                                                          sync.Mutex
	preference                                                         sync.Mutex
	backend                                                            photoPolicyBackend
	state                                                              localPhotoPolicyStatus
	master, masterKnown, preferenceKnown, journalKnown, journalPending bool
	revision, preferenceRevision                                       uint64
	root                                                               string
	savePreference                                                     func(bool) error
	readPreference                                                     func() (bool, error)
	classicClear                                                       func() bool
	classicResume                                                      func()
	wake                                                               chan struct{}
}

func newLocalPhotoPolicyController(b photoPolicyBackend) *localPhotoPolicyController {
	return &localPhotoPolicyController{backend: b, wake: make(chan struct{}, 1), state: localPhotoPolicyStatus{Available: true, Phase: "waiting_master_decision", Persistence: "unknown"}}
}
func (c *localPhotoPolicyController) snapshot() localPhotoPolicyStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}
func (c *localPhotoPolicyController) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
func (c *localPhotoPolicyController) blocksClassic() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.masterKnown || !c.preferenceKnown || !c.journalKnown || c.journalPending || c.state.Requested || c.state.SavedEnabled || c.state.PolicyArmed
}
func (c *localPhotoPolicyController) configure(save func(bool) error, read func() (bool, error)) {
	c.mu.Lock()
	c.savePreference = save
	c.readPreference = read
	c.mu.Unlock()
}
func (c *localPhotoPolicyController) masterChanged(on bool) {
	c.mu.Lock()
	c.master = on
	c.masterKnown = true
	c.revision++
	rev := c.revision
	c.state.Requested = false
	if on {
		c.preferenceRevision = rev
		c.state.Persistence = "loading"
		c.state.Busy = true
	} else {
		c.state.Phase = "recovering"
	}
	read := c.readPreference
	c.mu.Unlock()
	c.signal()
	if on {
		go c.persist(rev, true, false, read, nil)
	}
}
func (c *localPhotoPolicyController) set(on bool, id string) error {
	if len(id) != 32 || strings.Trim(id, "0123456789abcdefABCDEF") != "" {
		return errors.New("PHOTO_POLICY_REQUEST_INVALID")
	}
	return WithLocalPhotoStrategySelection(func() error {
		clear := !on || c.classicClear == nil || c.classicClear()
		c.mu.Lock()
		defer c.mu.Unlock()
		code := ""
		if on && !c.master {
			code = "PHOTO_POLICY_DEBUG_REQUIRED"
		} else if !clear {
			code = "PHOTO_POLICY_RUNTIME_ISOLATION_CONFLICT"
		}
		if code != "" {
			c.state.RejectedID = id
			c.state.RejectedError = code
			return errors.New(code)
		}
		c.revision++
		rev := c.revision
		c.preferenceRevision = rev
		c.state.RequestID = id
		c.state.RejectedID = ""
		c.state.RejectedError = ""
		c.state.Requested = on
		c.state.Persistence = "saving"
		c.state.Busy = true
		c.state.Error = ""
		if !on {
			c.state.Phase = "recovering"
		}
		save := c.savePreference
		go c.persist(rev, false, on, nil, save)
		c.signal()
		return nil
	})
}
func (c *localPhotoPolicyController) persist(rev uint64, restore, on bool, read func() (bool, error), save func(bool) error) {
	c.preference.Lock()
	defer c.preference.Unlock()
	c.mu.Lock()
	current := c.preferenceRevision == rev
	c.mu.Unlock()
	if !current {
		return
	}
	var err error
	if restore {
		if read == nil {
			err = errors.New("PHOTO_POLICY_PREFERENCE_UNAVAILABLE")
		} else {
			on, err = read()
		}
	} else if save == nil {
		err = errors.New("PHOTO_POLICY_PREFERENCE_UNAVAILABLE")
	} else {
		err = save(on)
	}
	_ = WithLocalPhotoStrategySelection(func() error {
		clear := !on || c.classicClear == nil || c.classicClear()
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.preferenceRevision != rev {
			return nil
		}
		c.state.Busy = false
		c.preferenceKnown = err == nil
		if err != nil {
			c.state.Persistence = "failed"
			c.state.Error = "PHOTO_POLICY_PREFERENCE_FAILED"
			c.state.Phase = "preference_failed"
			c.state.Requested = false
			return nil
		}
		c.state.Persistence = "saved"
		c.state.SavedEnabled = on
		c.state.Error = ""
		if c.revision == rev {
			c.state.Requested = on && c.master && clear
		}
		if !clear {
			c.state.Error = "PHOTO_POLICY_RUNTIME_ISOLATION_CONFLICT"
			c.state.Phase = "strategy_conflict"
		}
		return nil
	})
	c.signal()
}
func (c *localPhotoPolicyController) allowed(rev uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.revision == rev && c.master && c.state.Requested && c.state.Persistence == "saved"
}
func (c *localPhotoPolicyController) bind(root string) error {
	c.mu.Lock()
	c.root = root
	c.mu.Unlock()
	c.signal()
	return nil
}
func (c *localPhotoPolicyController) publish(phase string, err error, j photoPolicyJournal, armed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.Phase = phase
	c.journalKnown = true
	c.journalPending = j.Captured || len(j.Entries) > 0
	c.state.OwnedNodes = len(j.Entries)
	c.state.PolicyArmed = armed
	c.state.Effective = false // Registry intent alone is not proof that Windows blocked a device.
	c.state.Busy = c.state.Persistence == "saving" || c.state.Persistence == "loading"
	if err != nil {
		code := err.Error()
		if len(code) > 96 || !strings.HasPrefix(code, "PHOTO_POLICY_") || strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" {
			code = "PHOTO_POLICY_NATIVE_FAILED"
		}
		c.state.Error = code
		c.state.CauseCode = code
		c.state.NativeKind = ""
		c.state.NativeCode = 0
		var failure *localPhotoFailure
		if errors.As(err, &failure) && (failure.kind == "WIN32" || failure.kind == "CONFIGRET") {
			c.state.NativeKind = failure.kind
			c.state.NativeCode = failure.native
		}
	} else if c.state.Persistence != "failed" && c.state.Error != "PHOTO_POLICY_RUNTIME_ISOLATION_CONFLICT" {
		c.state.Error = ""
		c.state.CauseCode = ""
		c.state.NativeKind = ""
		c.state.NativeCode = 0
	}
}
func (c *localPhotoPolicyController) step() {
	c.operation.Lock()
	defer c.operation.Unlock()
	if c.backend == nil {
		return
	}
	unlock, err := c.backend.lock()
	if err != nil {
		c.mu.Lock()
		c.state.Error = "PHOTO_POLICY_STORE_BUSY"
		c.state.Phase = "recovery_pending"
		c.mu.Unlock()
		return
	}
	defer unlock()
	j, err := c.backend.load()
	if err != nil {
		c.mu.Lock()
		c.state.Error = "PHOTO_POLICY_JOURNAL_UNREADABLE"
		c.state.Phase = "recovery_pending"
		c.mu.Unlock()
		return
	}
	_ = WithLocalPhotoStrategySelection(func() error {
		clear := c.classicClear == nil || c.classicClear()
		c.mu.Lock()
		defer c.mu.Unlock()
		if clear && c.master && c.preferenceKnown && c.state.SavedEnabled && c.state.Error == "PHOTO_POLICY_RUNTIME_ISOLATION_CONFLICT" {
			c.state.Requested = true
			c.state.Error = ""
		}
		return nil
	})
	c.mu.Lock()
	known, master, persistence, requested, rev, root := c.masterKnown, c.master, c.state.Persistence, c.state.Requested, c.revision, c.root
	c.mu.Unlock()
	if !known || master && (persistence == "unknown" || persistence == "loading") {
		c.publish("waiting_master_decision", nil, j, false)
		return
	}
	if master && requested && c.classicClear != nil && !c.classicClear() {
		c.mu.Lock()
		if c.revision == rev {
			c.state.Requested = false
			c.state.Error = "PHOTO_POLICY_RUNTIME_ISOLATION_CONFLICT"
		}
		c.mu.Unlock()
		requested = false
	}
	if !master || !requested {
		had := j.Captured
		err = restorePhotoPolicy(c.backend)
		fresh, loadErr := c.backend.load()
		if loadErr == nil {
			j = fresh
		}
		if err != nil || loadErr != nil {
			c.publish("recovery_pending", errors.New("PHOTO_POLICY_RESTORE_PENDING"), j, false)
			return
		}
		c.mu.Lock()
		if had {
			c.state.RestoreRequiresReenumeration = true
		}
		conflict := c.state.Error == "PHOTO_POLICY_RUNTIME_ISOLATION_CONFLICT"
		c.mu.Unlock()
		phase := "off"
		if conflict {
			phase = "strategy_conflict"
		} else if had {
			phase = "restore_waiting_reenumeration"
		}
		c.publish(phase, nil, j, false)
		if c.classicResume != nil && !c.blocksClassic() {
			c.classicResume()
		}
		return
	}
	if persistence != "saved" {
		c.publish("waiting_preference", nil, j, false)
		return
	}
	if err = c.backend.supported(); err != nil {
		c.mu.Lock()
		c.state.Available = false
		c.mu.Unlock()
		c.publish("unsupported", err, j, false)
		return
	}
	if root == "" && len(j.Entries) > 0 {
		// A previous authorized journal may continue across boot, but cannot
		// discover additional IDs until a fresh authorized bind arrives.
		err = continuePhotoPolicy(c.backend, j, func() bool { return c.allowed(rev) })
		if err != nil {
			c.publish("policy_pending", err, j, false)
		} else {
			c.publish("policy_armed_waiting_reenumeration", nil, j, true)
		}
		return
	}
	if root == "" {
		c.publish("waiting_authorized_target", nil, j, false)
		return
	}
	scan, err := c.backend.scan(root)
	c.mu.Lock()
	c.state.ObservedNodes = len(scan.Nodes)
	c.state.PresentNodes = scan.Present
	c.state.UnhealthyNodes = scan.Unhealthy
	c.state.RestartRequired = scan.RestartRequired
	c.mu.Unlock()
	if err != nil {
		c.publish("target_unproven", err, j, false)
		return
	}
	if scan.RestartRequired || scan.Unhealthy > 0 {
		code := "PHOTO_POLICY_NATIVE_UNHEALTHY"
		if scan.RestartRequired {
			code = "PHOTO_POLICY_NATIVE_RESTART_REQUIRED"
		}
		c.publish("native_unhealthy", errors.New(code), j, false)
		return
	}
	err = applyPhotoPolicy(c.backend, scan.Nodes, func() bool { return c.allowed(rev) })
	fresh, loadErr := c.backend.load()
	if loadErr == nil {
		j = fresh
	}
	if !c.allowed(rev) {
		_ = restorePhotoPolicy(c.backend)
		c.signal()
		return
	}
	if err != nil || loadErr != nil {
		if err == nil {
			err = errors.New("PHOTO_POLICY_JOURNAL_UNREADABLE")
		}
		c.publish("policy_pending", err, j, false)
		return
	}
	phase := "waiting_photo_interface"
	armed := len(j.Entries) > 0
	if armed {
		phase = "policy_armed_waiting_reenumeration"
	}
	c.publish(phase, nil, j, armed)
}
func (c *localPhotoPolicyController) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		c.step()
		select {
		case <-ctx.Done():
			c.mu.Lock()
			retain := !c.masterKnown || c.master && (c.state.Persistence == "loading" || c.state.Persistence == "unknown" || c.state.SavedEnabled && c.state.Requested)
			c.state.RetainedOnExit = retain
			if !retain {
				c.master = false
				c.masterKnown = true
			}
			c.mu.Unlock()
			if !retain {
				c.step()
			}
			return
		case <-tick.C:
		case <-c.wake:
		}
	}
}
