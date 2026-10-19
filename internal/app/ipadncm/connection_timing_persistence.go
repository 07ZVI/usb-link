//go:build usblink_local_remote

package ipadncm

import (
	"fmt"
	"time"
)

func validConnectionTimingMode(mode string) bool {
	return mode == "normal" || mode == "fast" || mode == "delayed"
}

func (c *connectionTimingController) configurePersistence(save func(string) error, restore func() (string, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initLocked()
	c.saveMode, c.restoreMode = save, restore
	c.restoreAllowed = true
}
func (c *connectionTimingController) resetRuntime() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initLocked()
	c.selectionRevision++
	c.restoreAllowed = true
	if c.state.Persistence == "loading" {
		c.state.Persistence = "unknown"
		if c.persistenceKnown {
			c.state.Persistence = "saved"
		}
	}
	_ = c.setLocked("normal", time.Now())
}

// File I/O is serialized independently of the short status lock. Reset changes
// the selection revision immediately, so an in-flight write may save intent but
// can never reactivate a profile after the master switch has closed it.
func (c *connectionTimingController) saveSelection(mode string, allowed func() bool) error {
	if !validConnectionTimingMode(mode) {
		return fmt.Errorf("CONNECTION_TIMING_MODE_INVALID")
	}
	c.mu.Lock()
	c.initLocked()
	c.selectionRevision++
	c.persistenceOperation++
	revision, operation := c.selectionRevision, c.persistenceOperation
	c.restoreAllowed = false
	c.state.Persistence = "saving"
	c.state.PersistenceError = ""
	save := c.saveMode
	if mode == "normal" {
		_ = c.setLocked("normal", time.Now())
	}
	c.mu.Unlock()
	c.persistenceIO.Lock()
	defer c.persistenceIO.Unlock()
	c.mu.Lock()
	current := operation == c.persistenceOperation
	c.mu.Unlock()
	if !current {
		return fmt.Errorf("CONNECTION_TIMING_SELECTION_CHANGED")
	}
	var err error
	if save == nil {
		err = fmt.Errorf("CONNECTION_TIMING_PERSISTENCE_UNAVAILABLE")
	} else {
		err = save(mode)
	}
	mayApply := mode == "normal" || allowed()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.state.SavedMode = mode
		c.persistenceKnown = true
	}
	if !mayApply && revision == c.selectionRevision {
		c.restoreAllowed = true
	}
	if operation != c.persistenceOperation {
		return fmt.Errorf("CONNECTION_TIMING_SELECTION_CHANGED")
	}
	if err != nil {
		c.state.Persistence = "failed"
		c.state.PersistenceError = "CONNECTION_TIMING_PREFERENCE_SAVE_FAILED"
		return fmt.Errorf("%s", c.state.PersistenceError)
	}
	c.state.Persistence = "saved"
	c.state.PersistenceError = ""
	if revision == c.selectionRevision && mayApply {
		_ = c.setLocked(mode, time.Now())
	}
	return nil
}

// A user selection disables automatic restore until the next master reset.
// This prevents even a late-scheduled startup restore from overriding a click.
func (c *connectionTimingController) restoreSelection(allowed func() bool) error {
	c.mu.Lock()
	c.initLocked()
	if !c.restoreAllowed {
		c.mu.Unlock()
		return nil
	}
	c.persistenceOperation++
	operation, revision := c.persistenceOperation, c.selectionRevision
	restore := c.restoreMode
	c.state.Persistence = "loading"
	c.state.PersistenceError = ""
	c.mu.Unlock()
	c.persistenceIO.Lock()
	defer c.persistenceIO.Unlock()
	c.mu.Lock()
	current := operation == c.persistenceOperation && revision == c.selectionRevision && c.restoreAllowed
	c.mu.Unlock()
	if !current {
		return nil
	}
	mode := "normal"
	var err error
	if restore == nil {
		err = fmt.Errorf("CONNECTION_TIMING_PERSISTENCE_UNAVAILABLE")
	} else {
		mode, err = restore()
	}
	if err == nil && !validConnectionTimingMode(mode) {
		err = fmt.Errorf("CONNECTION_TIMING_PREFERENCE_INVALID")
	}
	mayApply := allowed()
	c.mu.Lock()
	defer c.mu.Unlock()
	if operation != c.persistenceOperation {
		return nil
	}
	if err != nil {
		c.state.Persistence = "failed"
		c.state.PersistenceError = "CONNECTION_TIMING_PREFERENCE_READ_FAILED"
		return fmt.Errorf("%s", c.state.PersistenceError)
	}
	c.state.SavedMode = mode
	c.persistenceKnown = true
	c.state.Persistence = "saved"
	c.state.PersistenceError = ""
	if revision == c.selectionRevision && c.restoreAllowed && mayApply {
		_ = c.setLocked(mode, time.Now())
		c.restoreAllowed = false
	}
	return nil
}
