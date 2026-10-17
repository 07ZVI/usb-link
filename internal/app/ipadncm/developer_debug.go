//go:build usblink_local_remote

package ipadncm

import (
	"errors"
	"sync"
)

func newUnavailableDeveloperDebugController(code string) *developerDebugController {
	err := errors.New(code)
	return &developerDebugController{
		state:     developerDebugSnapshot{Available: true, Persistence: "failed", Error: code, USBPhase: "failed"},
		save:      func(bool) error { return err },
		restore:   func() (bool, error) { return false, err },
		apply:     func(bool) (string, error) { return "", err },
		intent:    func(bool) error { return err },
		transport: func() (bool, bool, string) { return false, false, "failed" },
	}
}

type developerDebugSnapshot struct {
	StartupError string `json:"startup_error,omitempty"`
	Available    bool   `json:"available"`
	Enabled      bool   `json:"enabled"`
	Busy         bool   `json:"busy"`
	Requested    bool   `json:"requested"`
	RequestID    string `json:"request_id"`
	Message      string `json:"message"`
	Error        string `json:"error,omitempty"`
	Persistence  string `json:"persistence"`
	SavedEnabled bool   `json:"saved_enabled"`
	USBPhase     string `json:"usb_phase"`
	USBEnabled   bool   `json:"usb_enabled"`
	USBReady     bool   `json:"usb_ready"`
}

// Local diagnostics are immediate. Persistence and USB authorization have their
// own confirmation; a failed USB setup must leave the diagnostic panel usable.
type developerDebugController struct {
	mu          sync.Mutex
	state       developerDebugSnapshot
	revision    uint64
	apply       func(bool) (string, error)
	save        func(bool) error
	restore     func() (bool, error)
	intent      func(bool) error
	intentError error
	transport   func() (bool, bool, string)
	// This callback only changes in-memory experiment authority. It must not do I/O
	// or call back into this controller while mu serializes the current intent.
	photoMaster func(bool)
}

func (c *developerDebugController) snapshot() developerDebugSnapshot {
	c.mu.Lock()
	state := c.state
	c.mu.Unlock()
	if !state.Busy && c.transport != nil {
		state.USBEnabled, state.USBReady, state.USBPhase = c.transport()
		if state.Error != "" {
			state.USBPhase = "failed"
		}
	}
	return state
}

func (c *developerDebugController) initialize() {
	desired, err := c.restore()
	c.mu.Lock()
	// A click made while the protected preference was being read wins.
	if c.revision != 0 {
		c.mu.Unlock()
		c.run()
		return
	}
	if err != nil {
		if c.photoMaster != nil {
			c.photoMaster(false)
		}
		c.state.Busy = false
		c.state.Persistence = "failed"
		c.state.Error = err.Error()
		c.state.USBPhase = "off"
		c.mu.Unlock()
		return
	}
	c.state.Persistence = "saved"
	c.state.SavedEnabled = desired
	c.state.Enabled = desired
	c.state.Requested = desired
	if c.intentError != nil {
		if c.photoMaster != nil {
			c.photoMaster(false)
		}
		c.state.Busy = false
		c.state.Error = c.intentError.Error()
		c.state.USBPhase = "failed"
		c.mu.Unlock()
		return
	}
	if !desired {
		if c.photoMaster != nil {
			c.photoMaster(false)
		}
		c.state.Busy = false
		c.state.USBPhase = "off"
		c.mu.Unlock()
		return
	}
	c.revision++
	c.state.USBPhase = "preparing"
	c.mu.Unlock()
	c.run()
}

func (c *developerDebugController) request(enabled bool, id string) {
	c.mu.Lock()
	c.revision++
	c.state.Requested, c.state.RequestID = enabled, id
	c.state.Enabled = enabled
	c.state.Message = ""
	c.state.Persistence = "saving"
	c.state.Error = ""
	c.state.USBEnabled = false
	c.state.USBReady = false
	c.state.USBPhase = "preparing"
	if !enabled {
		c.state.USBPhase = "revoking"
	}
	if c.photoMaster != nil {
		c.photoMaster(false)
	}
	// Admission closes synchronously, even while an earlier enable is in flight.
	if c.intent != nil {
		c.intentError = c.intent(false)
		if c.intentError != nil {
			c.state.Error = c.intentError.Error()
		}
	}
	if c.state.Busy {
		c.mu.Unlock()
		return
	}
	c.state.Busy = true
	c.mu.Unlock()
	go c.run()
}

func (c *developerDebugController) run() {
	for {
		c.mu.Lock()
		revision, desired, intentErr := c.revision, c.state.Requested, c.intentError
		c.mu.Unlock()
		var saveErr error
		if c.save != nil {
			saveErr = c.save(desired)
		}
		c.mu.Lock()
		if saveErr == nil {
			c.state.SavedEnabled = desired
		}
		if revision != c.revision {
			c.mu.Unlock()
			continue
		}
		if saveErr == nil {
			c.state.Persistence = "saved"
		} else {
			c.state.Persistence = "failed"
		}
		if c.intent != nil {
			if e := c.intent(desired && saveErr == nil && intentErr == nil); intentErr == nil {
				intentErr = e
			}
		}
		// Publish photo authority under the same revision lock as requests. The
		// slow apply below can be stale by the time it starts and must not grant it.
		if c.photoMaster != nil {
			c.photoMaster(desired && saveErr == nil && intentErr == nil)
		}
		c.mu.Unlock()
		message := ""
		err := intentErr
		if err == nil {
			err = saveErr
		}
		// Off still revokes this process when saving off failed. On never grants
		// network authority unless the protected preference was saved and read back.
		if (saveErr == nil && intentErr == nil) || !desired {
			var applyErr error
			message, applyErr = c.apply(desired)
			if err == nil {
				err = applyErr
			}
		}
		c.mu.Lock()
		if revision == c.revision {
			c.state.Message = message
			c.state.Error = ""
			if err != nil {
				c.state.Error = err.Error()
				if len(c.state.Error) > 512 {
					c.state.Error = c.state.Error[:512]
				}
			}
			c.state.Busy = false
			if err != nil {
				c.state.USBPhase = "failed"
			} else if !desired {
				c.state.USBPhase = "off"
			}
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
	}
}
