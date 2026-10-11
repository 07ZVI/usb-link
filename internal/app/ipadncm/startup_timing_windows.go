//go:build windows && amd64

package ipadncm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/app/startuptelemetry"
	"suhang/usbnet/internal/app/usbhost"
	"sync"
)

var startupTimingSignals = make(chan struct{}, 1)
var startupTimingOnce struct {
	host                    sync.Once
	macPresent, ipadPresent sync.Once
}
var startupReadyObserved struct {
	sync.Mutex
	mac, ipad bool
}

func signalStartupTiming() {
	select {
	case startupTimingSignals <- struct{}{}:
	default:
	}
}

// A freshly authenticated local owner's login anchor changes diagnostics only.
func RecordAuthenticatedLogonTiming(session uint32) {
	if startuptelemetry.ObserveAuthenticatedSession(session) {
		signalStartupTiming()
	}
}
func RecordSharedHostTiming() {
	startupTimingOnce.host.Do(func() { startuptelemetry.RecordSharedHostReady(); signalStartupTiming() })
}

func init() {
	observeStartupReadiness = func(r ApplicationResult) {
		var present *sync.Once
		var ready *bool
		switch r.DeviceKind {
		case "Mac":
			present, ready = &startupTimingOnce.macPresent, &startupReadyObserved.mac
		case "iPad":
			present, ready = &startupTimingOnce.ipadPresent, &startupReadyObserved.ipad
		default:
			return
		}
		if r.Status == "WAITING_SHARED_HOST" {
			present.Do(func() { startuptelemetry.RecordDevicePresent(r.DeviceKind); signalStartupTiming() })
		}
		if startupNetworkReady(r) {
			if startuptelemetry.AttachmentAwaitingReady(r.DeviceKind) {
				if _, valid := usbhost.Proof(); valid && startuptelemetry.RecordAttachmentReady(r.DeviceKind) {
					signalStartupTiming()
				}
			}
			startupReadyObserved.Lock()
			if !*ready {
				// Recheck current published host proof on the first candidate only.
				// Failed proof does not consume the latch; a later valid session can.
				if _, valid := usbhost.Proof(); valid {
					startuptelemetry.RecordDeviceReady(r.DeviceKind)
					*ready = true
					signalStartupTiming()
				}
			}
			startupReadyObserved.Unlock()
		}
	}
}

// Diagnostic output only: this protected file is never read for authority or
// recovery. Write on the five bounded event changes, not on a periodic timer.
func StartStartupTimingEvidence(ctx context.Context, recoveryDir, version string) func() {
	// The caller holds the protected recovery store owner. Avoid writing as an
	// administrator through a user-writable LOCALAPPDATA directory junction.
	dir := recoveryDir
	if !networkOnlyDriverStoreProtected(dir) {
		return func() {}
	}
	path := filepath.Join(dir, fmt.Sprintf("startup-timing-%s-process-%d-%d.json", version, os.Getpid(), startuptelemetry.Snapshot().Anchors.CapturedAt.UnixNano()))
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		write := func() {
			b, e := json.MarshalIndent(startuptelemetry.Snapshot(), "", "  ")
			if e != nil {
				return
			}
			// A fresh temporary leaf avoids following a pre-existing output symlink.
			f, name, e := createPortableProtectedTemp(dir)
			if e != nil {
				return
			}
			defer os.Remove(name)
			_, e = f.Write(append(b, '\n'))
			if e == nil {
				e = f.Sync()
			}
			closeErr := f.Close()
			if e == nil && closeErr == nil {
				_ = os.Rename(name, path)
			}
		}
		write()
		for {
			select {
			case <-ctx.Done():
				write()
				return
			case <-startupTimingSignals:
				write()
			}
		}
	}()
	return func() { cancel(); <-done }
}
