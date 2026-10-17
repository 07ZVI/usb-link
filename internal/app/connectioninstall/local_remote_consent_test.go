//go:build usblink_local_remote

package connectioninstall

import (
	"errors"
	"sync/atomic"
	"testing"
)

func TestLocalRemoteConsentOffInvalidatesInflightEnableEpoch(t *testing.T) {
	var gate localRemoteConsentGate
	var desired, receipt atomic.Bool
	if err := gate.selectIntent(true, desired.Store, nil); err != nil {
		t.Fatal(err)
	}
	old := gate.epoch()
	if err := gate.selectIntent(false, desired.Store, func() error { receipt.Store(false); return nil }); err != nil {
		t.Fatal(err)
	}
	// A subsequent on cannot revive the old enable's epoch.
	if err := gate.selectIntent(true, desired.Store, nil); err != nil {
		t.Fatal(err)
	}
	write := func() error { receipt.Store(true); return nil }
	if err := gate.write(true, old, desired.Load, write); err == nil || receipt.Load() {
		t.Fatal("old enable rewrote revoked consent", err)
	}
	if err := gate.write(true, gate.epoch(), desired.Load, write); err != nil || !receipt.Load() {
		t.Fatal("fresh explicit selection did not authorize receipt", err)
	}
}

func TestLocalRemoteConsentOffSerializesOnlyReceiptWrite(t *testing.T) {
	var gate localRemoteConsentGate
	var desired, receipt atomic.Bool
	_ = gate.selectIntent(true, desired.Store, nil)
	epoch := gate.epoch()
	entered, release := make(chan struct{}), make(chan struct{})
	written := make(chan error, 1)
	go func() {
		written <- gate.write(true, epoch, desired.Load, func() error {
			close(entered)
			<-release
			receipt.Store(true)
			return nil
		})
	}()
	<-entered
	revoked := make(chan error, 1)
	intentClosed := make(chan struct{})
	go func() {
		first := true
		revoked <- gate.selectIntent(false, func(v bool) {
			desired.Store(v)
			if first {
				close(intentClosed)
				first = false
			}
		}, func() error { receipt.Store(false); return nil })
	}()
	<-intentClosed
	if desired.Load() {
		t.Fatal("off waited for receipt before closing network admission")
	}
	close(release)
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := <-revoked; err != nil || receipt.Load() {
		t.Fatal("off returned with enabled receipt", err)
	}
}

func TestLocalRemoteConsentRevocationFailureIsNotSuccess(t *testing.T) {
	var gate localRemoteConsentGate
	var desired atomic.Bool
	desired.Store(true)
	err := gate.selectIntent(false, desired.Store, func() error { return errors.New("private provider text") })
	if err == nil || err.Error() != "LOCAL_REMOTE_CONSENT_REVOCATION_FAILED" || desired.Load() {
		t.Fatal(err, desired.Load())
	}
}
