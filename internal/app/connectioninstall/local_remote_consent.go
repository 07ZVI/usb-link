//go:build usblink_local_remote

package connectioninstall

import (
	"errors"
	"sync"
)

// This lock protects only receipt writes. Off never waits for network cleanup
// or the manager lock. An in-flight enable must still own its selection epoch.
type localRemoteConsentGate struct {
	mu       sync.Mutex
	revision uint64
}

func (g *localRemoteConsentGate) selectIntent(enabled bool, set func(bool), revoke func() error) error {
	if !enabled {
		set(false)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.revision++
	set(enabled)
	if !enabled {
		if err := revoke(); err != nil {
			return errors.New("LOCAL_REMOTE_CONSENT_REVOCATION_FAILED")
		}
	}
	return nil
}

func (g *localRemoteConsentGate) epoch() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.revision
}

func (g *localRemoteConsentGate) write(enabled bool, revision uint64, desired func() bool, persist func() error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if enabled && (revision != g.revision || !desired()) {
		return errors.New("LOCAL_REMOTE_CONSENT_EXPIRED_OR_REVOKED")
	}
	return persist()
}
