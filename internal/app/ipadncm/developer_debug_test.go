//go:build usblink_local_remote

package ipadncm

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeveloperDebugStrictInitializationFailureStillAllowsInspection(t *testing.T) {
	const code = "LOCAL_REMOTE_INITIALIZATION_ROOT_FAILED"
	c := newUnavailableDeveloperDebugController(code)
	if s := c.snapshot(); !s.Available || s.Busy || s.Persistence != "failed" || s.Error != code {
		t.Fatal(s)
	}
	c.request(true, "inspect")
	if s := waitDeveloperDebug(t, c); !s.Enabled || s.SavedEnabled || s.Persistence != "failed" || s.Error != code || s.USBReady || s.USBEnabled {
		t.Fatal("unavailable backend claimed saved consent or USB authority", s)
	}
	c.request(false, "close")
	if s := waitDeveloperDebug(t, c); s.Enabled || s.USBReady || s.USBEnabled || s.Error != code {
		t.Fatal(s)
	}
}

func TestDeveloperDebugOffRevokesReceiptBeforeSlowPreferenceSave(t *testing.T) {
	var receipt atomic.Bool
	receipt.Store(true)
	entered, release := make(chan struct{}), make(chan struct{})
	c := &developerDebugController{
		intent: func(on bool) error { receipt.Store(on); return nil },
		save:   func(bool) error { close(entered); <-release; return nil },
		apply:  func(bool) (string, error) { return "", nil },
	}
	c.request(false, "off")
	<-entered
	if receipt.Load() {
		t.Fatal("preference save delayed cross-process revocation")
	}
	close(release)
	if s := waitDeveloperDebug(t, c); s.Error != "" || s.Enabled {
		t.Fatal(s)
	}
}

func TestDeveloperDebugRevocationFailureIsVisibleAndBlocksEnable(t *testing.T) {
	for _, on := range []bool{false, true} {
		var calls atomic.Int32
		c := &developerDebugController{
			intent: func(bool) error { return errors.New("LOCAL_REMOTE_CONSENT_REVOCATION_FAILED") },
			save:   func(bool) error { return nil },
			apply:  func(bool) (string, error) { calls.Add(1); return "", nil },
		}
		c.request(on, "revocation-failure")
		if s := waitDeveloperDebug(t, c); s.Error != "LOCAL_REMOTE_CONSENT_REVOCATION_FAILED" || s.USBPhase != "failed" || s.USBEnabled || (on && calls.Load() != 0) || (!on && calls.Load() != 1) {
			t.Fatal("revocation failure hidden or enabled transport", s, calls.Load())
		}
	}
}

func TestDeveloperDebugNetworkInitializationFailureCanRetrySavedIntent(t *testing.T) {
	for _, savedOn := range []bool{false, true} {
		var attempts atomic.Int32
		var allowed atomic.Bool
		var saved atomic.Bool
		saved.Store(savedOn)
		c := &developerDebugController{
			state:   developerDebugSnapshot{Available: true, Busy: true},
			restore: func() (bool, error) { return saved.Load(), nil },
			save:    func(on bool) error { saved.Store(on); return nil },
			intent:  func(on bool) error { allowed.Store(on); return nil },
			apply: func(on bool) (string, error) {
				if !on {
					return "", nil
				}
				if attempts.Add(1) == 1 {
					return "", errors.New("LOCAL_REMOTE_INITIALIZATION_LEGACY_FIREWALL_FAILED")
				}
				return "ready", nil
			},
		}
		c.initialize()
		if !savedOn {
			if attempts.Load() != 0 || allowed.Load() {
				t.Fatal("off preference retried USB enable")
			}
			c.request(true, "explicit-on")
		}
		if s := waitDeveloperDebug(t, c); !s.Enabled || !s.SavedEnabled || s.Persistence != "saved" || s.USBPhase != "failed" || s.Error == "" {
			t.Fatal("network error hid diagnostics or blocked independent preference", s)
		}
		c.request(true, "retry")
		if s := waitDeveloperDebug(t, c); !s.Enabled || s.Error != "" || attempts.Load() != 2 {
			t.Fatal("retry failed", s, attempts.Load())
		}
	}
}

func waitDeveloperDebug(t *testing.T, c *developerDebugController) developerDebugSnapshot {
	t.Helper()
	timeout := time.After(2 * time.Second)
	for {
		state := c.snapshot()
		if !state.Busy {
			return state
		}
		select {
		case <-timeout:
			t.Fatal("debug control did not finish")
			return state
		case <-time.After(time.Millisecond):
		}
	}
}

func TestDeveloperDebugLatestOffRevokesInFlightEnable(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	var actual atomic.Bool
	calls := make(chan bool, 2)
	c := &developerDebugController{state: developerDebugSnapshot{Available: true}, apply: func(on bool) (string, error) {
		calls <- on
		if on {
			close(entered)
			<-finish
		}
		actual.Store(on)
		return "", nil
	}}
	c.request(true, "first")
	<-entered
	state := c.snapshot()
	if !state.Busy || !state.Enabled || state.USBReady {
		t.Fatal("diagnostics did not open immediately or USB falsely ready", state)
	}
	c.request(false, "last")
	close(finish)
	state = waitDeveloperDebug(t, c)
	if state.Enabled || state.Requested || state.RequestID != "last" || actual.Load() {
		t.Fatal("last close lost", state)
	}
	if !<-calls || <-calls {
		t.Fatal("changes were not serialized")
	}
}

func TestDeveloperDebugFailureUsesActualBackendState(t *testing.T) {
	c := &developerDebugController{state: developerDebugSnapshot{Available: true}, apply: func(bool) (string, error) { return "", errors.New("USB_LOCAL_PUSH_TEST_FAILURE") }}
	c.request(true, "failure")
	state := waitDeveloperDebug(t, c)
	if !state.Enabled || state.USBReady || state.Error != "USB_LOCAL_PUSH_TEST_FAILURE" || state.RequestID != "failure" {
		t.Fatal(state)
	}
}

func TestDeveloperDebugSaveFailureDoesNotAuthorizeUSB(t *testing.T) {
	for _, on := range []bool{true, false} {
		calls := 0
		allowed := false
		c := &developerDebugController{save: func(bool) error { return errors.New("LOCAL_DEBUG_PREFERENCE_SAVE_FAILED") }, intent: func(v bool) error { allowed = v; return nil }, apply: func(bool) (string, error) { calls++; return "", nil }}
		c.request(on, "save-failed")
		state := waitDeveloperDebug(t, c)
		if state.Enabled != on || state.Persistence != "failed" || state.Error != "LOCAL_DEBUG_PREFERENCE_SAVE_FAILED" || allowed || (on && calls != 0) || (!on && calls != 1) {
			t.Fatal(on, state, calls, allowed)
		}
	}
}

func TestDeveloperDebugRestoresIntentWithFreshAuthorization(t *testing.T) {
	for _, on := range []bool{false, true} {
		var applied, saved atomic.Int32
		c := &developerDebugController{state: developerDebugSnapshot{Busy: true, Persistence: "loading"}, restore: func() (bool, error) { return on, nil }, save: func(v bool) error {
			if !v {
				t.Error("unexpected off save")
			}
			saved.Add(1)
			return nil
		}, apply: func(v bool) (string, error) {
			if !v {
				t.Error("unexpected off apply")
			}
			applied.Add(1)
			return "", nil
		}}
		c.initialize()
		state := c.snapshot()
		expected := int32(0)
		if on {
			expected = 1
		}
		if state.Busy || state.Enabled != on || state.SavedEnabled != on || state.Persistence != "saved" || applied.Load() != expected || saved.Load() != expected {
			t.Fatal(state, applied.Load(), saved.Load())
		}
	}
}

func TestDeveloperDebugClickWinsOverSlowRestore(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	calls := make(chan bool, 1)
	c := &developerDebugController{state: developerDebugSnapshot{Busy: true}, restore: func() (bool, error) { close(entered); <-finish; return true, nil }, apply: func(v bool) (string, error) { calls <- v; return "", nil }}
	go c.initialize()
	<-entered
	c.request(false, "new-off")
	close(finish)
	state := waitDeveloperDebug(t, c)
	if state.Enabled || state.SavedEnabled || state.RequestID != "new-off" || <-calls {
		t.Fatal(state)
	}
}

func TestDeveloperDebugUSBPreparationDoesNotHoldStatusOrAdmission(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	var admitted atomic.Bool
	c := &developerDebugController{intent: func(v bool) error { admitted.Store(v); return nil }, save: func(bool) error { return nil }, apply: func(v bool) (string, error) {
		if v {
			close(entered)
			<-finish
		}
		return "", nil
	}}
	c.request(true, "on")
	<-entered
	state := c.snapshot()
	if !state.Enabled || !state.Busy || state.Persistence != "saved" || state.USBPhase != "preparing" || state.USBReady {
		t.Fatal(state)
	}
	c.request(false, "off")
	if admitted.Load() {
		t.Fatal("close did not revoke admission while apply was blocked")
	}
	close(finish)
	state = waitDeveloperDebug(t, c)
	if state.Enabled || state.SavedEnabled || state.USBPhase != "off" {
		t.Fatal(state)
	}
}

func TestDeveloperDebugUnreadablePreferenceNeverEnables(t *testing.T) {
	c := &developerDebugController{state: developerDebugSnapshot{Busy: true}, restore: func() (bool, error) { return true, errors.New("LOCAL_DEBUG_PREFERENCE_READ_FAILED") }, apply: func(bool) (string, error) { t.Fatal("unexpected authorization"); return "", nil }}
	c.initialize()
	state := c.snapshot()
	if state.Enabled || state.Busy || state.Persistence != "failed" || state.Error == "" {
		t.Fatal(state)
	}
}

func TestDeveloperDebugStaleApplyCannotRestorePhotoAuthorityAfterOff(t *testing.T) {
	photo := newLocalPhotoController(newPhotoFake())
	photo.configure(func(bool) error { return nil }, func() (bool, error) { return true, nil })
	onEntered, onRelease := make(chan struct{}), make(chan struct{})
	offEntered, offRelease := make(chan struct{}), make(chan struct{})
	c := &developerDebugController{
		photoMaster: photo.masterChanged,
		apply: func(on bool) (string, error) {
			if on {
				close(onEntered)
				<-onRelease
			} else {
				close(offEntered)
				<-offRelease
			}
			return "", nil
		},
	}
	c.request(true, "on")
	<-onEntered
	waitPhotoPref(t, photo, "saved")
	if !photo.snapshot().Requested {
		t.Fatal("current saved-on intent did not restore photo preference")
	}
	c.request(false, "off")
	if photo.snapshot().Requested || photo.authorized(0, "") {
		t.Fatal("off left photo authority enabled during the old apply")
	}
	close(onRelease)
	<-offEntered
	photo.mu.Lock()
	master := photo.master
	photo.mu.Unlock()
	if master || photo.snapshot().Requested {
		t.Fatal("stale apply reenabled photo before off network cleanup finished")
	}
	close(offRelease)
	if s := waitDeveloperDebug(t, c); s.Enabled || s.Requested {
		t.Fatal(s)
	}
}

func TestDeveloperDebugPhotoRevocationPrecedesConsentIO(t *testing.T) {
	var photoAllowed atomic.Bool
	photoAllowed.Store(true)
	entered, release, requested := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var intentCalls atomic.Int32
	c := &developerDebugController{
		photoMaster: photoAllowed.Store,
		intent: func(bool) error {
			if intentCalls.Add(1) == 1 {
				close(entered)
				<-release
			}
			return nil
		},
		apply: func(bool) (string, error) { return "", nil },
	}
	go func() { c.request(false, "off"); close(requested) }()
	<-entered
	if photoAllowed.Load() {
		t.Fatal("consent storage delayed photo revocation")
	}
	close(release)
	<-requested
	waitDeveloperDebug(t, c)
}

func TestDeveloperDebugPhotoAuthorityRequiresSavedCurrentIntent(t *testing.T) {
	for _, failure := range []string{"save", "intent"} {
		t.Run(failure, func(t *testing.T) {
			var granted atomic.Bool
			c := &developerDebugController{
				photoMaster: func(on bool) {
					if on {
						granted.Store(true)
					}
				},
				save: func(bool) error {
					if failure == "save" {
						return errors.New("SAVE_FAILED")
					}
					return nil
				},
				intent: func(on bool) error {
					if on && failure == "intent" {
						return errors.New("INTENT_FAILED")
					}
					return nil
				},
				apply: func(bool) (string, error) { t.Error("failed intent reached apply"); return "", nil },
			}
			c.request(true, "on")
			if s := waitDeveloperDebug(t, c); s.Error == "" || granted.Load() {
				t.Fatal("failed persistence or consent granted photo authority", s)
			}
		})
	}
}
