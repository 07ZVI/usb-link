//go:build usblink_local_remote

package ipadncm

import (
	"context"
	"sync/atomic"
	"testing"
)

func TestDefaultIsolationApplicationCancellationWaitsForExplicitCleanup(t *testing.T) {
	f := newPhotoFake()
	n := photoNode("OWNED")
	f.nodes = []portableNodeReceipt{n}
	p := newLocalPhotoController(f)
	active := true
	p.runtimeAllowed = func() bool { return active }
	p.runtimeDefault(true)
	p.root = n.Root
	p.step()
	if f.disables != 1 || p.snapshot().OwnedNodes != 1 {
		t.Fatal("photo fixture not isolated")
	}
	active = false
	for i := 0; i < 3; i++ {
		p.step()
	}
	if f.restores != 0 || p.snapshot().OwnedNodes != 1 {
		t.Fatal("photo restored before network cleanup")
	}
	p.runtimeDefault(false)
	p.step()
	if f.restores != 1 || p.snapshot().OwnedNodes != 0 {
		t.Fatal("photo not restored after explicit stop")
	}

	a := newLocalAMDSHoldController()
	b := &amdsHoldFake{}
	a.backend = b
	active = true
	a.runtimeAllowed = func() bool { return active }
	a.runtimeDefault(true)
	a.step()
	if b.starts.Load() != 1 {
		t.Fatal("AMDS fixture not held")
	}
	active = false
	for i := 0; i < 3; i++ {
		a.step()
	}
	if b.stops.Load() != 0 {
		t.Fatal("AMDS restored before network cleanup")
	}
	a.runtimeDefault(false)
	a.step()
	if b.stops.Load() != 1 {
		t.Fatal("AMDS not restored after explicit stop")
	}
}

func TestDefaultIsolationCancellationDuringServiceStartWaitsForWorkerJoin(t *testing.T) {
	b := &amdsHoldFake{begin: make(chan struct{}), release: make(chan struct{})}
	c := newLocalAMDSHoldController()
	c.backend = b
	var active atomic.Bool
	active.Store(true)
	c.runtimeAllowed = active.Load
	c.runtimeDefault(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.ctx = ctx
	done := make(chan struct{})
	go c.run(ctx, done)
	<-b.begin
	active.Store(false) // Application cancellation, before session cleanup.
	close(b.release)
	// operation joins the in-flight native start without invoking restoration.
	c.operation.Lock()
	c.operation.Unlock()
	if b.stops.Load() != 0 {
		t.Fatal("cancelled start restored before session cleanup")
	}
	c.runtimeDefault(false)
	cancel() // Explicit Stop after network owner has joined.
	<-done
	if b.stops.Load() == 0 {
		t.Fatal("worker exit omitted restoration")
	}
}
