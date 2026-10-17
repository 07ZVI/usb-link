//go:build usblink_local_remote

package connectioninstall

import (
	"errors"
	"sync/atomic"
	"testing"
)

func TestLocalRemoteStartupCleanupBlocksCredentialsUntilComplete(t *testing.T) {
	failure := errors.New("provider-private-text")
	var s localRemoteStartupCleanup
	s.record("local_firewall", failure)
	s.record("legacy_firewall", failure)
	localCalls, legacyCalls, activations := 0, 0, 0
	localFail, legacyFail := true, true
	local := func() error {
		localCalls++
		if localFail {
			return failure
		}
		return nil
	}
	legacy := func() error {
		legacyCalls++
		if legacyFail {
			return failure
		}
		return nil
	}
	activate := func() error { activations++; return nil }
	on := func() bool { return true }
	if err := s.prepare(true, on, local, legacy, activate); RemoteInitializationCode(err) != "LOCAL_REMOTE_INITIALIZATION_LOCAL_FIREWALL_FAILED" || activations != 0 || legacyCalls != 0 {
		t.Fatal("local failure reached credentials/listener", err, activations, legacyCalls)
	}
	localFail = false
	if err := s.prepare(true, on, local, legacy, activate); RemoteInitializationCode(err) != "LOCAL_REMOTE_INITIALIZATION_LEGACY_FIREWALL_FAILED" || activations != 0 || !s.pending() {
		t.Fatal("legacy failure reached credentials/listener", err, activations)
	}
	legacyFail = false
	if err := s.prepare(true, on, local, legacy, activate); err != nil || activations != 1 || s.pending() || localCalls != 3 || legacyCalls != 2 {
		t.Fatal("retry failed or duplicated cleanup", err, localCalls, legacyCalls, activations)
	}
	if RemoteInitializationCode(s.firstError) != "LOCAL_REMOTE_INITIALIZATION_LOCAL_FIREWALL_FAILED" {
		t.Fatal("original startup evidence lost")
	}
	if err := s.prepare(true, on, local, legacy, activate); err != nil || legacyCalls != 2 {
		t.Fatal("successful legacy cleanup repeated", err, legacyCalls)
	}
}

func TestLocalRemoteStartupCleanupOffDuringRetryCannotActivate(t *testing.T) {
	var s localRemoteStartupCleanup
	s.record("legacy_firewall", errors.New("failed"))
	var desired atomic.Bool
	desired.Store(true)
	entered, resume := make(chan struct{}), make(chan struct{})
	var activated atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- s.prepare(true, desired.Load, func() error { return nil }, func() error { close(entered); <-resume; return nil }, func() error { activated.Store(true); return nil })
	}()
	<-entered
	desired.Store(false)
	close(resume)
	if err := <-done; err != nil || activated.Load() || s.pending() {
		t.Fatal("off during cleanup reopened admission", err)
	}
	// Even a stale true intent cannot turn an explicit off operation into on.
	desired.Store(true)
	if err := s.prepare(false, desired.Load, func() error { return nil }, nil, func() error { activated.Store(true); return nil }); err != nil || activated.Load() {
		t.Fatal("off activated", err)
	}
}
