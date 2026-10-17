//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"context"
	"errors"
	"strings"
	"suhang/usbnet/internal/buildinfo"
	"sync"
	"time"
)

var localPhoto = newLocalPhotoController(nil)
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
func SetPhotoIsolationPersistence(save func(bool) error, read func() (bool, error)) {
	localPhoto.configure(save, read)
}
func SetPhotoIsolationMaster(on bool) {
	localPhoto.masterChanged(on && buildinfo.LocalDiagnostics == "true")
}
func SetPhotoIsolation(on bool, id string) error {
	if on && buildinfo.LocalDiagnostics != "true" {
		localPhoto.mu.Lock()
		if len(id) == 32 && strings.Trim(id, "0123456789abcdefABCDEF") == "" {
			localPhoto.state.RejectedID = id
			localPhoto.state.RejectedError = "PHOTO_LOCAL_DIAGNOSTICS_REQUIRED"
		}
		localPhoto.mu.Unlock()
		return errors.New("PHOTO_LOCAL_DIAGNOSTICS_REQUIRED")
	}
	return localPhoto.set(on, id)
}
func PhotoIsolationDiagnostics() any { return localPhoto.snapshot() }

// Callers must already hold the normal network/identity consent scope. This
// binding does not infer such authority from a preference or display prefix.
func BindPhotoIsolationTarget(s Snapshot) error {
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
