//go:build windows && amd64

package ipadncm

import (
	"context"
	"sync"
	"testing"
)

func TestUpgradeCancelsOnlyIdleOwnedQueuesAndKeepsRecoveryState(t *testing.T) {
	// Package tests run without device setup. No platform mutation or durable
	// writer is involved in this callback; cancelled queues cannot be consumed.
	networkOnly.Lock()
	oldNetworkPending, oldNetworkBusy, oldEnabled, oldStatus := networkOnly.pending, networkOnly.busy, networkOnly.enabled, networkOnly.status
	networkOnly.pending, networkOnly.busy, networkOnly.enabled = true, false, true
	networkOnly.Unlock()
	oldReserved := ipadUpgradeReserved.Load()
	ipadUpgradeReserved.Store(false)
	defer func() {
		networkOnly.Lock()
		networkOnly.pending, networkOnly.busy, networkOnly.enabled, networkOnly.status = oldNetworkPending, oldNetworkBusy, oldEnabled, oldStatus
		networkOnly.Unlock()
		ipadUpgradeReserved.Store(oldReserved)
	}()
	release, err := reserveIPadUpgrade()
	if err != nil {
		t.Fatal(err)
	}
	if NetworkOnlyPending() || !ipadUpgradeReserved.Load() {
		t.Fatal("idle queue was retained or no reservation")
	}
	networkOnly.Lock()
	unchanged := networkOnly.enabled
	networkOnly.Unlock()
	if !unchanged {
		t.Fatal("upgrade changed the user choice")
	}
	if _, err = reserveIPadUpgrade(); err == nil {
		t.Fatal("duplicate reservation accepted")
	}
	if RunPendingNetworkOnly(context.Background(), true) {
		t.Fatal("cancelled queue executed")
	}
	if RequestNetworkOnly(false) == nil {
		t.Fatal("settings admitted during staging reservation")
	}
	// All ordinary children attached while staging owns the reservation must
	// be cancelled before their caller can proceed into native inspection.
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ctx, cancel := context.WithCancel(context.Background())
			AdmitIPadAttempt(cancel)
			if ctx.Err() == nil {
				t.Error("new ordinary attempt escaped upgrade reservation")
			}
		}()
	}
	workers.Wait()
	release()
	release()
	if ipadUpgradeReserved.Load() {
		t.Fatal("release not idempotent")
	}
	networkOnly.Lock()
	networkOnly.busy = true
	networkOnly.Unlock()
	if _, err = reserveIPadUpgrade(); err == nil {
		t.Fatal("executing network-only request cancelled for upgrade")
	}
}
