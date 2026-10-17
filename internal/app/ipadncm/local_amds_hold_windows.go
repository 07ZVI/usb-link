//go:build windows && amd64

package ipadncm

import (
	"context"
	"errors"
	"sync"
	"time"
)

var localAMDSHold = newLocalAMDSHoldController()
var localAMDSHoldStart sync.Once

func StartLocalAMDSHold(ctx context.Context, dir string) func() {
	var stop func()
	localAMDSHoldStart.Do(func() {
		run, cancel := context.WithCancel(ctx)
		localAMDSHold.mu.Lock()
		localAMDSHold.ctx = run
		localAMDSHold.mu.Unlock()
		localAMDSHold.stamp = func() (string, string, int64) {
			now := time.Now()
			id, ms := trustDiagnostics.stamp(now)
			return now.UTC().Format(time.RFC3339Nano), id, ms
		}
		localAMDSHold.backend = &localAMDSHoldNative{dir: dir}
		done := make(chan struct{})
		go localAMDSHold.run(run, done)
		stop = func() { cancel(); <-done }
	})
	if stop == nil {
		return func() {}
	}
	return stop
}

// Compatibility entry points cannot override the ordinary network lifecycle.
func SetLocalAMDSHoldPersistence(func(bool) error, func() (bool, error)) {}
func SetLocalAMDSHoldMaster(bool)                                        {}
func SetLocalAMDSHold(bool, string) error                                { return errors.New("AMDS_AUTOMATIC_RUNTIME_POLICY") }
func LocalAMDSHoldDiagnostics() any                                      { return localAMDSHold.snapshot() }
