package usbhost

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestLateJoinCancelsDeviceBeforeReleasingHost(t *testing.T) {
	host, stopHost := context.WithCancel(context.Background())
	var acquired, released atomic.Int32
	a := NewAttemptLease(context.Background(), func(context.Context) (context.Context, func(), bool) {
		acquired.Add(1)
		return host, func() { released.Add(1) }, true
	})
	if acquired.Load() != 0 {
		t.Fatal("early preparation acquired host")
	}
	if err := a.Join(); err != nil {
		t.Fatal(err)
	}
	if err := a.Join(); err != nil {
		t.Fatal(err)
	}
	if acquired.Load() != 1 {
		t.Fatal("duplicate generation lease")
	}
	stopHost()
	select {
	case <-a.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("device not cancelled")
	}
	if released.Load() != 0 {
		t.Fatal("host released before device cleanup")
	}
	if !a.Invalidated() {
		t.Fatal("missing invalidation")
	}
	a.Close()
	a.Close()
	if released.Load() != 1 {
		t.Fatal("lease not released once")
	}
}
func TestCancelledHostJoinCannotProceed(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	a := NewAttemptLease(parent, func(ctx context.Context) (context.Context, func(), bool) { <-ctx.Done(); return nil, nil, false })
	done := make(chan error, 1)
	go func() { done <- a.Join() }()
	cancel()
	if <-done == nil {
		t.Fatal("cancel accepted")
	}
	a.Close()
}
