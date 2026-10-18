//go:build windows && amd64

package ipadncm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

var localPhoto = func() *localPhotoController {
	c := newLocalPhotoController(nil)
	c.policyBlocked = func() bool { return !defaultIsolationReady.Load() }
	return c
}()
var localPhotoStart sync.Once

func StartPhotoIsolation(ctx context.Context, dir string) func() {
	var stop func()
	localPhotoStart.Do(func() {
		localPhoto.operation = &localPhotoNativeMutex
		localPhoto.backend = &localPhotoNativeBackend{dir: dir}
		run, cancel := context.WithCancel(ctx)
		localPhoto.context = run
		localPhoto.stamp = func() (string, string, int64) {
			now := time.Now()
			id, ms := trustDiagnostics.stamp(now)
			return now.UTC().Format(time.RFC3339Nano), id, ms
		}
		done := make(chan struct{})
		go localPhoto.run(run, done)
		stop = func() { cancel(); <-done }
	})
	if stop == nil {
		return func() {}
	}
	return stop
}

// Compatibility entry points cannot override the ordinary network lifecycle.
func SetPhotoIsolationPersistence(func(bool) error, func() (bool, error)) {}
func SetPhotoIsolationMaster(bool)                                        {}
func SetPhotoIsolation(bool, string) error                                { return errors.New("PHOTO_AUTOMATIC_RUNTIME_POLICY") }
func PhotoIsolationDiagnostics() any                                      { return localPhoto.snapshot() }

// Before a mode request: put every remembered instance of the bound iPad into
// the isolated state so the instance that arrives afterwards starts disabled.
// Best effort by design; a failure is reported in status and never blocks the
// network path.
func ApplyPhotoIsolationBeforeModeRequest() {
	if defaultIsolationAdmission() == nil {
		localPhoto.applyKnown()
	}
}

// Callers must already hold the normal network/identity consent scope. This
// binding does not infer such authority from a preference or display prefix.
func BindPhotoIsolationTarget(s Snapshot) error {
	if err := defaultIsolationAdmission(); err != nil {
		return err
	}
	if !networkOnlyUSBEligible(s) {
		return errors.New("PHOTO_ROOT_UNPROVEN")
	}
	root := ""
	for _, n := range s.Nodes {
		if !strings.EqualFold(n.IDPrefix, `USB\VID_05AC&PID_12AB`) {
			continue
		}
		if root != "" || n.instanceID == "" || !strings.HasPrefix(strings.ToUpper(n.instanceID), `USB\VID_05AC&PID_12AB\`) {
			return errors.New("PHOTO_ROOT_AMBIGUOUS")
		}
		root = n.instanceID
	}
	if root == "" {
		return errors.New("PHOTO_ROOT_UNPROVEN")
	}
	return localPhoto.bind(root)
}
