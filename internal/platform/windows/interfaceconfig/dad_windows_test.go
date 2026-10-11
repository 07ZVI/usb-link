//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"errors"
	"testing"
)

func TestDisabledDoesNotReadOrMutate(t *testing.T) {
	SetDADZeroEnabled(false)
	SetPersistentEnabled(false)
	calls := 0
	verify := func() error { calls++; return nil }
	o, e := ApplyDADZero(context.Background(), "not-a-store", Scope{}, verify)
	if e != nil || o.Code != "DISABLED" || calls != 0 {
		t.Fatal(o, e, calls)
	}
	o, e = ApplyPersistentHost(context.Background(), "not-a-store", Scope{}, verify, ProfileOps{})
	if e != nil || o.Code != "DISABLED" || calls != 0 {
		t.Fatal(o, e, calls)
	}
}

func TestOwnedDADDisabledAndOwnerRejectionCannotTouchStore(t *testing.T) {
	old := OwnedDADZeroEnabled()
	defer SetOwnedDADZeroEnabled(old)
	SetOwnedDADZeroEnabled(false)
	calls := 0
	o, e := ApplyOwnedDADZero(context.Background(), "not-a-store", OwnedDADIdentity{}, func() error { calls++; return nil })
	if e != nil || o.Code != "DISABLED" || calls != 0 {
		t.Fatal(o, e, calls)
	}
	SetOwnedDADZeroEnabled(true)
	id := testOwnedDAD().Originals[0].Identity
	o, e = ApplyOwnedDADZero(context.Background(), "not-a-store", id, func() error { calls++; return errors.New("denied") })
	if e == nil || o.Verified || calls != 1 {
		t.Fatal(o, e, calls)
	}
}
func TestFreshScopeCannotUseAliasOrMemory(t *testing.T) {
	if fresh(context.Background(), Scope{Role: "host", GUID: MacGUID, Index: 1, LUID: 1}, func() error { return nil }) == nil {
		t.Fatal("wrong fixed GUID")
	}
	if fresh(context.Background(), Scope{Role: "host", GUID: HostGUID, Index: 1, LUID: 1}, nil) == nil {
		t.Fatal("missing owner callback")
	}
}
