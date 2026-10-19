//go:build usblink_local_remote

package ipadncm

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func waitTimingPersistence(t *testing.T, c *connectionTimingController, want string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if c.snapshot().Persistence == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("persistence state did not arrive", want, c.snapshot())
}
func TestConnectionTimingPreferenceRestoreAndMasterReset(t *testing.T) {
	var c connectionTimingController
	stored := "delayed"
	c.configurePersistence(func(mode string) error { stored = mode; return nil }, func() (string, error) { return stored, nil })
	if err := c.restoreSelection(func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if s := c.snapshot(); s.Mode != "delayed" || s.SavedMode != "delayed" || s.Persistence != "saved" {
		t.Fatal(s)
	}
	c.resetRuntime()
	if s := c.snapshot(); s.Mode != "normal" || s.SavedMode != "delayed" || stored != "delayed" {
		t.Fatal(s)
	}
	if err := c.restoreSelection(func() bool { return true }); err != nil || c.snapshot().Mode != "delayed" {
		t.Fatal(err, c.snapshot())
	}
	if err := c.saveSelection("normal", func() bool { return false }); err != nil || stored != "normal" || c.snapshot().Mode != "normal" {
		t.Fatal(err, stored, c.snapshot())
	}
}

func TestConnectionTimingSaveFailureKeepsOldProfileButNormalCancelsImmediately(t *testing.T) {
	var c connectionTimingController
	fail := false
	c.configurePersistence(func(string) error {
		if fail {
			return errors.New("disk failure")
		}
		return nil
	}, nil)
	if err := c.saveSelection("delayed", func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := c.saveSelection("fast", func() bool { return true }); err == nil {
		t.Fatal("save failure hidden")
	}
	if s := c.snapshot(); s.Mode != "delayed" || s.SavedMode != "delayed" || s.Persistence != "failed" || s.PersistenceError == "" {
		t.Fatal(s)
	}
	plan := c.plan(time.Now())
	if err := c.saveSelection("normal", func() bool { return false }); err == nil {
		t.Fatal("normal save failure hidden")
	}
	select {
	case <-plan.changed:
	default:
		t.Fatal("normal did not cancel the old delay")
	}
	if s := c.snapshot(); s.Mode != "normal" || s.SavedMode != "delayed" || s.Persistence != "failed" {
		t.Fatal(s)
	}
}

func TestConnectionTimingResetDuringSaveDoesNotReopen(t *testing.T) {
	var c connectionTimingController
	var enabled atomic.Bool
	enabled.Store(true)
	entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	stored := "normal"
	c.configurePersistence(func(mode string) error { close(entered); <-finish; stored = mode; return nil }, func() (string, error) { return stored, nil })
	go func() { done <- c.saveSelection("delayed", enabled.Load) }()
	<-entered
	enabled.Store(false)
	c.resetRuntime()
	if c.snapshot().Mode != "normal" {
		t.Fatal("reset waited for disk write")
	}
	close(finish)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s := c.snapshot(); s.Mode != "normal" || s.SavedMode != "delayed" || s.Persistence != "saved" {
		t.Fatal(s)
	}
	enabled.Store(true)
	if err := c.restoreSelection(enabled.Load); err != nil || c.snapshot().Mode != "delayed" {
		t.Fatal(err, c.snapshot())
	}
}

func TestConnectionTimingSlowRestoreCannotOverrideNewSelection(t *testing.T) {
	var c connectionTimingController
	entered, finish := make(chan struct{}), make(chan struct{})
	restoreDone, saveDone := make(chan error, 1), make(chan error, 1)
	stored := "delayed"
	c.configurePersistence(func(mode string) error { stored = mode; return nil }, func() (string, error) { close(entered); <-finish; return stored, nil })
	go func() { restoreDone <- c.restoreSelection(func() bool { return true }) }()
	<-entered
	go func() { saveDone <- c.saveSelection("fast", func() bool { return true }) }()
	waitTimingPersistence(t, &c, "saving")
	close(finish)
	if err := <-restoreDone; err != nil {
		t.Fatal(err)
	}
	if err := <-saveDone; err != nil {
		t.Fatal(err)
	}
	if s := c.snapshot(); s.Mode != "fast" || s.SavedMode != "fast" || stored != "fast" {
		t.Fatal(s, stored)
	}
}

func TestConnectionTimingLateRestoreDoesNotReplaceUserChoice(t *testing.T) {
	var c connectionTimingController
	reads := 0
	c.configurePersistence(func(string) error { return nil }, func() (string, error) { reads++; return "delayed", nil })
	if err := c.saveSelection("fast", func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if err := c.restoreSelection(func() bool { return true }); err != nil || reads != 0 || c.snapshot().Mode != "fast" {
		t.Fatal(err, reads, c.snapshot())
	}
}

func TestConnectionTimingInvalidPreferenceNeverActivates(t *testing.T) {
	for _, value := range []string{"untrusted", ""} {
		var c connectionTimingController
		c.configurePersistence(nil, func() (string, error) { return value, nil })
		if err := c.restoreSelection(func() bool { return true }); err == nil || c.snapshot().Mode != "normal" || c.snapshot().Persistence != "failed" {
			t.Fatal(err, c.snapshot())
		}
	}
}

func TestConnectionTimingResetWhileRestoreQueuedDoesNotStayLoading(t *testing.T) {
	var c connectionTimingController
	c.configurePersistence(nil, func() (string, error) { t.Error("obsolete restore performed IO"); return "delayed", nil })
	c.persistenceIO.Lock()
	done := make(chan error, 1)
	go func() { done <- c.restoreSelection(func() bool { return true }) }()
	waitTimingPersistence(t, &c, "loading")
	c.resetRuntime()
	if s := c.snapshot(); s.Mode != "normal" || s.Persistence == "loading" {
		t.Fatal(s)
	}
	c.persistenceIO.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s := c.snapshot(); s.Mode != "normal" || s.Persistence == "loading" {
		t.Fatal(s)
	}
}
