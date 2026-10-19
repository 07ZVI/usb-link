package connectioninstall

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInstallationUIWaitReturnsPromptlyWhenClientsClose(t *testing.T) {
	var stops atomic.Int32
	var polls atomic.Int32
	start := time.Now()
	err := waitInstallationUIExit(context.Background(), 2, func(i int) (bool, error) { return polls.Add(1) > 2, nil }, time.Second, 5*time.Second, time.Millisecond, func() error { stops.Add(1); return nil })
	if err != nil || stops.Load() != 0 || time.Since(start) > time.Second {
		t.Fatal("prompt close was delayed or stopped the core", err, stops.Load())
	}
}

func TestInstallationUIWaitStopsCoreOnceAfterGraceForClientsThatIgnoreClose(t *testing.T) {
	var stopped atomic.Bool
	var stops atomic.Int32
	err := waitInstallationUIExit(context.Background(), 1, func(int) (bool, error) { return stopped.Load(), nil }, 20*time.Millisecond, 2*time.Second, time.Millisecond, func() error {
		stops.Add(1)
		stopped.Store(true) // The client treats the stopped core as the installer drain and ends.
		return nil
	})
	if err != nil || stops.Load() != 1 {
		t.Fatal("a client ignoring the close request was not released by stopping the core", err, stops.Load())
	}
}

func TestInstallationUIWaitNeverKillsAndReportsStillRunning(t *testing.T) {
	err := waitInstallationUIExit(context.Background(), 1, func(int) (bool, error) { return false, nil }, time.Millisecond, 30*time.Millisecond, time.Millisecond, func() error { return nil })
	if err == nil || !strings.HasPrefix(err.Error(), "INSTALL_UI_STILL_RUNNING") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if err := waitInstallationUIExit(context.Background(), 1, func(int) (bool, error) { return false, nil }, time.Millisecond, time.Second, time.Millisecond, func() error { return errors.New("stop failed") }); err == nil || err.Error() != "stop failed" {
		t.Fatal("a failed core stop must abort the installation", err)
	}
}

func TestInstallationPhaseActive(t *testing.T) {
	for p, want := range map[InstallationPhase]bool{
		InstallStaged: true, InstallQuiescing: true, InstallPreviousBound: true, InstallPublished: true, InstallStarted: true,
		InstallAccepted: true, InstallCleaning: true, InstallRestoring: true,
		InstallComplete: false, InstallRolledBack: false, "": false, "bogus": false,
	} {
		if InstallationPhaseActive(p) != want {
			t.Fatal(p)
		}
	}
}
