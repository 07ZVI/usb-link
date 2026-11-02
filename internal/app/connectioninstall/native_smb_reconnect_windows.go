//go:build windows && amd64

package connectioninstall

import (
	"context"
	"fmt"
	"strings"
	"suhang/usbnet/internal/security/deviceguard"
	"suhang/usbnet/internal/sharing/fileshare"
	"sync"
	"time"
)

var smbReconnectStatus struct {
	sync.Mutex
	LastCheck time.Time
	Problem   string
	Restored  int
}

func nativeSMBReconnectDiagnostics() any {
	smbReconnectStatus.Lock()
	defer smbReconnectStatus.Unlock()
	return struct {
		LastCheck time.Time `json:"last_check"`
		Problem   string    `json:"problem"`
		Restored  int       `json:"restored"`
	}{smbReconnectStatus.LastCheck, smbReconnectStatus.Problem, smbReconnectStatus.Restored}
}

// A service-owned loop also works in session 0, with no open renderer/window.
// Probe only selected GUID roots with live publication receipts, never scan
// disks by drive letter/name. Short-lived catalog handles permit safe ejection.
func WatchNativeSMBVolumes(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		events, unsubscribe, registrationError := deviceguard.SubscribeFilteredChanges(func(id string) bool {
			id = strings.ToUpper(id)
			return strings.HasPrefix(id, `USBSTOR\`) || strings.HasPrefix(id, `SCSI\DISK`) || strings.HasPrefix(id, `STORAGE\VOLUME`)
		})
		if unsubscribe != nil {
			defer unsubscribe()
		}
		// Native notifications can precede mounting. Recheck only during a
		// bounded settling window on startup or after an event; no periodic disk I/O when
		// notifications are healthy and the machine is idle.
		var fallback <-chan time.Time
		if registrationError != nil {
			ticker := time.NewTicker(4 * time.Second)
			defer ticker.Stop()
			fallback = ticker.C
		}
		settling := time.NewTimer(time.Second)
		defer settling.Stop()
		var retry <-chan time.Time = settling.C
		delay := time.Second
		tracker := smbReconnectTracker{}
		reconcile := true
		for {
			if ctx.Err() != nil {
				return
			}
			restored, err := checkNativeSMBVolumes(ctx, tracker, &reconcile)
			smbReconnectStatus.Lock()
			smbReconnectStatus.LastCheck = time.Now()
			// Keep the last recovery error until a successful recovery; an ordinary
			// idle poll must not erase evidence of a failed bounded retry.
			if err != nil {
				smbReconnectStatus.Problem = err.Error()
			}
			if restored > 0 {
				smbReconnectStatus.Restored += restored
				smbReconnectStatus.Problem = ""
			}
			smbReconnectStatus.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-fallback:
			case <-events:
				reconcile = true // A coalesced detach/attach need not expose an offline sample.
				if !settling.Stop() {
					select {
					case <-settling.C:
					default:
					}
				}
				delay = time.Second
				settling.Reset(delay)
				retry = settling.C
			case <-retry:
				if delay < 32*time.Second {
					delay *= 2
					settling.Reset(delay)
				} else {
					retry = nil
				}
			}
		}
	}()
	return func() { cancel(); <-done }
}

func checkNativeSMBVolumes(ctx context.Context, tracker smbReconnectTracker, reconcile *bool) (int, error) {
	nativeSMBMu.Lock()
	config, err := loadNativeSMB()
	nativeSMBMu.Unlock()
	if err != nil {
		return 0, err
	}
	eligible := map[string]bool{}
	for _, s := range config.Shares {
		if fileshare.IsVolumePath(s.Path) {
			eligible[s.ID] = true
		}
	}
	if len(eligible) == 0 {
		tracker.observe(nil)
		*reconcile = false
		return 0, nil
	}
	cat, err := ShareCatalog()
	if err != nil {
		return 0, err
	}
	cat.Refresh() // No journal rewrite for unchanged availability observations.
	var rows []smbReconnectObservation
	for _, f := range cat.List() {
		if eligible[f.ID] && fileshare.IsVolumePath(f.Path) && f.Identity != "" {
			rows = append(rows, smbReconnectObservation{f.ID, f.Path, f.Identity, f.Available})
		}
	}
	if *reconcile {
		tracker.arm(rows)
		*reconcile = false
	}
	restored := 0
	var firstError error
	for _, id := range tracker.observe(rows) {
		if ctx.Err() != nil {
			return restored, ctx.Err()
		}
		if err := restoreReconnectedSMBVolume(ctx, cat, id); err != nil {
			if firstError == nil {
				firstError = err
			}
		} else {
			tracker.restored(id)
			restored++
		}
	}
	return restored, firstError
}

func restoreReconnectedSMBVolume(ctx context.Context, cat *fileshare.Catalog, id string) error {
	nativeSMBOperationMu.Lock()
	defer nativeSMBOperationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	// Recheck membership after waiting for any explicit off/remove operation.
	nativeSMBMu.Lock()
	defer func() { nativeSMBMu.Unlock(); invalidateNativeSMB() }()
	config, err := loadNativeSMB()
	if err != nil {
		return err
	}
	var receipt *nativeSMBShare
	for _, s := range config.Shares {
		if s.ID == id {
			copy := s
			receipt = &copy
			break
		}
	}
	if receipt == nil {
		return nil
	} // Explicitly disabled/removed while probing.
	s := *receipt
	if s.AccessUpdate || s.GuestUpdate || s.MigrationName != "" {
		return fmt.Errorf("SMB_RECONNECT_RECOVERY_PENDING")
	}
	cat.Refresh()
	for _, f := range cat.List() {
		if f.ID != id {
			continue
		}
		if !f.Available || !fileshare.IsVolumePath(f.Path) || !strings.EqualFold(f.Path, s.Path) || f.Identity == "" {
			return fmt.Errorf("SMB_RECONNECT_ROOT_UNAVAILABLE")
		}
		// Refresh proves the original volume+directory identity under its owner.
		// Readback in addNativeShare refuses any externally changed/name-conflicting
		// share, preserving its permissions instead of overwriting it.
		if err = ensureNativeSMB(); err != nil {
			return err
		}
		got, free, rc, e := getNativeShare(s.Name)
		if e != nil {
			return e
		}
		if rc == 0 {
			owned := ownedNativeShare(s, got)
			free()
			if !owned {
				return fmt.Errorf("NATIVE_SMB_CHANGED_IN_WINDOWS: %s", s.Name)
			}
			return nil
		}
		if rc != 2310 {
			return fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc)
		}
		sids := []string{s.SID}
		if s.GuestSID != "" {
			sids = append(sids, s.GuestSID)
		}
		if e = grantSMBRoot(f.ID, f.Path, sids); e != nil {
			return e
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		return addNativeShare(s)
	}
	return nil
}
