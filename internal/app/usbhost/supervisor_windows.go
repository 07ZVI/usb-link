//go:build windows && amd64

package usbhost

import (
	"context"
	"sync"
)

var supervisedHost struct {
	sync.Mutex
	s *Supervisor
}

func StartSharedHostSupervisor(ctx context.Context, prepare func(context.Context) (PreparedHost, error)) func() {
	supervisedHost.Lock()
	if supervisedHost.s != nil {
		supervisedHost.Unlock()
		panic("shared host supervisor already started")
	}
	s := NewSupervisor(ctx, prepare)
	supervisedHost.s = s
	supervisedHost.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() { s.Close(); supervisedHost.Lock(); supervisedHost.s = nil; supervisedHost.Unlock() })
	}
}

func currentSupervisor() *Supervisor {
	supervisedHost.Lock()
	defer supervisedHost.Unlock()
	return supervisedHost.s
}
func sharedHostPublished() bool { s := currentSupervisor(); return s != nil && s.Ready() }
func NudgeSharedHost() {
	if s := currentSupervisor(); s != nil {
		s.Nudge()
	}
}
func SharedHostSupervisorDetails() any {
	if s := currentSupervisor(); s != nil {
		return s.Snapshot()
	}
	return SupervisorSnapshot{State: "not_started"}
}
func AcquireSharedHost(ctx context.Context) (context.Context, func(), bool) {
	if s := currentSupervisor(); s != nil {
		return s.Acquire(ctx)
	}
	return nil, nil, false
}
