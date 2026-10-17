package ipadncm

import (
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestDefaultIsolationMigratesBeforeActivatingAndStopsWithoutReactivation(t *testing.T) {
	var calls []string
	c := &defaultIsolationLifecycle{}
	c.policy = func() error { calls = append(calls, "policy"); return nil }
	c.photo = func() error { calls = append(calls, "photo"); return nil }
	c.amds = func() error { calls = append(calls, "amds"); return nil }
	c.activate = func() { calls = append(calls, "activate") }
	c.quiesce = func() { calls = append(calls, "join") }
	if err := c.start(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"policy", "amds", "photo", "activate"}) {
		t.Fatal(calls)
	}
	if c.snapshot().Restored {
		t.Fatal("running isolation is not restored")
	}
	if err := c.stop(); err != nil {
		t.Fatal(err)
	}
	if err := c.stop(); err != nil {
		t.Fatal(err)
	}
	if err := c.start(); err == nil {
		t.Fatal("exit restarted isolation")
	}
	want := []string{"policy", "amds", "photo", "activate", "join", "policy", "amds", "photo", "policy", "amds", "photo"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatal(calls)
	}
	s := c.snapshot()
	if !s.Restored || !s.PolicyRestored || !s.PhotoRestored || !s.AMDSRestored || s.Phase != "restored" || s.Error != "" {
		t.Fatal(s)
	}
}

func TestDefaultIsolationFailedMigrationNeverActivatesAndRecoveryCanRetry(t *testing.T) {
	fail := true
	activates, joins, amds, photo := 0, 0, 0, 0
	c := &defaultIsolationLifecycle{
		policy: func() error {
			if fail {
				return errors.New("foreign policy changed")
			}
			return nil
		},
		amds: func() error { amds++; return nil }, photo: func() error { photo++; return nil },
		activate: func() { activates++ }, quiesce: func() { joins++ },
	}
	if c.start() == nil || activates != 0 || amds != 1 || photo != 1 {
		t.Fatal("failed migration enabled isolation")
	}
	if c.stop() == nil || c.snapshot().Restored {
		t.Fatal("failed policy restoration reported success")
	}
	s := c.snapshot()
	if s.PolicyRestored || !s.AMDSRestored || !s.PhotoRestored || s.Error != "NETWORK_ISOLATION_RESTORE_PENDING" {
		t.Fatal(s)
	}
	fail = false
	if c.stop() != nil || !c.snapshot().Restored || activates != 0 || joins != 1 {
		t.Fatal("retry did not restore independently")
	}
}

func TestDefaultIsolationExitRevokesConcurrentMigration(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	activates := 0
	c := &defaultIsolationLifecycle{
		policy: func() error { once.Do(func() { close(entered); <-release }); return nil },
		amds:   func() error { return nil }, photo: func() error { return nil }, activate: func() { activates++ }, quiesce: func() {},
	}
	started := make(chan struct{})
	go func() { _ = c.start(); close(started) }()
	<-entered
	// stop publishes this before waiting for the native-operation mutex.
	c.revoked.Store(true)
	stopped := make(chan struct{})
	go func() { _ = c.stop(); close(stopped) }()
	close(release)
	<-started
	<-stopped
	if activates != 0 || !c.snapshot().Restored {
		t.Fatal("pending activation survived exit")
	}
}

func TestDefaultIsolationAllRestorationFailuresStayVisible(t *testing.T) {
	for _, which := range []string{"policy", "photo", "amds"} {
		t.Run(which, func(t *testing.T) {
			failure := func(name string) func() error {
				return func() error {
					if name == which {
						return errors.New("native failure")
					}
					return nil
				}
			}
			c := &defaultIsolationLifecycle{policy: failure("policy"), photo: failure("photo"), amds: failure("amds"), activate: func() {}, quiesce: func() {}}
			if c.stop() == nil {
				t.Fatal("missing restoration error")
			}
			s := c.snapshot()
			if s.Restored || s.Busy || s.Phase != "recovery_pending" {
				t.Fatal(s)
			}
		})
	}
}

func TestDefaultIsolationRuntimeChoiceDoesNotReadOrWriteDebugPreferences(t *testing.T) {
	p := newLocalPhotoController(nil)
	p.configure(func(bool) error { t.Fatal("wrote debug preference"); return nil }, func() (bool, error) { t.Fatal("read debug preference"); return false, nil })
	p.runtimeDefault(true)
	s := p.snapshot()
	if !s.Requested || s.Persistence != "saved" || s.SavedEnabled {
		t.Fatal(s)
	}
	p.runtimeDefault(false)
	if p.snapshot().Requested {
		t.Fatal("photo not revoked")
	}
	a := newLocalAMDSHoldController()
	a.configure(func(bool) error { t.Fatal("wrote AMDS preference"); return nil }, func() (bool, error) { t.Fatal("read AMDS preference"); return false, nil })
	a.runtimeDefault(true)
	if !a.allowed(a.revision) {
		t.Fatal("default AMDS not enabled")
	}
	a.runtimeAllowed = func() bool { return false }
	if a.allowed(a.revision) {
		t.Fatal("runtime revocation ignored")
	}
	a.runtimeDefault(false)
	if a.snapshot().Requested {
		t.Fatal("AMDS not revoked")
	}
}
