//go:build windows && amd64

package usbhost

import (
	"context"
	"errors"
	"testing"
)

func TestRestoreFactoryRequiresFreshInstalledOwnerWithoutNativeCall(t *testing.T) {
	if e := RestorePersistentHostFactoryForUninstall(context.Background(), "not-a-source", "not-a-dll"); e == nil {
		t.Fatal("legacy source-only entry gained uninstall creator authority")
	}
	if e := RestorePersistentHostFactoryForUninstallVerified(context.Background(), "not-a-source", "not-a-dll", nil); e == nil {
		t.Fatal("missing installed owner accepted")
	}
	denied := errors.New("fixed owner rejected")
	calls := 0
	if e := RestorePersistentHostFactoryForUninstallVerified(context.Background(), "not-a-source", "not-a-dll", func() error { calls++; return denied }); !errors.Is(e, denied) || calls != 1 {
		t.Fatal("unproved coordinator reached native entry")
	}
	ctx := context.WithValue(context.Background(), persistentRestoreOwnerKey{}, func() error {
		calls++
		if calls > 2 {
			return denied
		}
		return nil
	})
	if e := verifyPersistentRestoreOwner(ctx); e != nil {
		t.Fatal(e)
	}
	if e := verifyPersistentRestoreOwner(ctx); !errors.Is(e, denied) {
		t.Fatal("changed coordinator proof reused cached success")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if verifyPersistentRestoreOwner(canceled) == nil {
		t.Fatal("canceled owner allowed mutation")
	}
}
