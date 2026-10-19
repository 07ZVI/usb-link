//go:build usblink_local_remote

package ipadncm

import (
	"errors"
	"strings"
	"sync"

	"suhang/usbnet/internal/transport/ncm"
)

// localMacMTUCapStatus is the bounded UI and diagnostics projection. The cap
// only takes effect when the next Mac session starts.
type localMacMTUCapStatus struct {
	Available     bool   `json:"available"`
	Busy          bool   `json:"busy"`
	Persistence   string `json:"persistence"`
	SavedCap      string `json:"saved_cap"`
	EffectiveCap  string `json:"effective_cap"`
	RequestID     string `json:"request_id,omitempty"`
	RejectedID    string `json:"rejected_id,omitempty"`
	RejectedError string `json:"rejected_error,omitempty"`
	Error         string `json:"error,omitempty"`
	Applies       string `json:"applies"`
}

type localMacMTUCapController struct {
	mu          sync.Mutex
	persistence sync.Mutex
	state       localMacMTUCapStatus
	saved       ncm.MTUCap
	master      bool
	revision    uint64
	save        func(string) error
	read        func() (string, error)
}

func newLocalMacMTUCapController() *localMacMTUCapController {
	return &localMacMTUCapController{state: localMacMTUCapStatus{Available: true, Persistence: "unknown", SavedCap: "auto", EffectiveCap: "auto", Applies: "next_connection"}}
}

func (c *localMacMTUCapController) configure(save func(string) error, read func() (string, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.save, c.read = save, read
}

func (c *localMacMTUCapController) snapshot() localMacMTUCapStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// effective is the cap the next Mac session must use. Without the developer
// master switch, or before the preference is proven, it is always auto.
func (c *localMacMTUCapController) effective() ncm.MTUCap {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.effectiveLocked()
}

func (c *localMacMTUCapController) effectiveLocked() ncm.MTUCap {
	if !c.master {
		return ncm.MTUCapAuto
	}
	return c.saved
}

func (c *localMacMTUCapController) refreshLocked() {
	c.state.SavedCap = c.saved.String()
	c.state.EffectiveCap = c.effectiveLocked().String()
}

func (c *localMacMTUCapController) masterChanged(on bool) {
	c.mu.Lock()
	c.master = on
	c.revision++
	rev := c.revision
	if on {
		c.state.Persistence, c.state.Busy = "loading", true
	} else {
		c.state.Busy = false
	}
	c.refreshLocked()
	c.mu.Unlock()
	if on {
		go c.persist(rev, true, ncm.MTUCapAuto)
	}
}

func (c *localMacMTUCapController) set(setting, id string) error {
	if len(id) != 32 || strings.Trim(id, "0123456789abcdefABCDEF") != "" {
		return errors.New("MAC_MTU_CAP_REQUEST_INVALID")
	}
	cap, err := ncm.ParseMTUCap(setting)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if !c.master {
		c.state.RejectedID, c.state.RejectedError = id, "MAC_MTU_CAP_DEBUG_REQUIRED"
		c.mu.Unlock()
		return errors.New("MAC_MTU_CAP_DEBUG_REQUIRED")
	}
	c.revision++
	rev := c.revision
	c.state.RequestID, c.state.RejectedID, c.state.RejectedError = id, "", ""
	c.state.Persistence, c.state.Busy = "saving", true
	c.mu.Unlock()
	go c.persist(rev, false, cap)
	return nil
}

func (c *localMacMTUCapController) persist(rev uint64, restore bool, want ncm.MTUCap) {
	c.persistence.Lock()
	defer c.persistence.Unlock()
	c.mu.Lock()
	if c.revision != rev {
		c.mu.Unlock()
		return
	}
	save, read := c.save, c.read
	c.mu.Unlock()
	var err error
	switch {
	case restore && read == nil, !restore && save == nil:
		err = errors.New("MAC_MTU_CAP_PREFERENCE_UNAVAILABLE")
	case restore:
		var text string
		if text, err = read(); err == nil {
			want, err = ncm.ParseMTUCap(text)
		}
	default:
		err = save(want.String())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.saved = want
	}
	if c.revision != rev {
		c.refreshLocked()
		return
	}
	c.state.Busy = false
	if err != nil {
		c.state.Persistence, c.state.Error = "failed", "MAC_MTU_CAP_PREFERENCE_FAILED"
	} else {
		c.state.Persistence, c.state.Error = "saved", ""
	}
	c.refreshLocked()
}
