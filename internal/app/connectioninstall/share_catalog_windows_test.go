//go:build windows && amd64

package connectioninstall

import (
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"testing"
)

// A Windows integration gate: verify the real thread token, callback errors and
// restoration. Cross-compilation alone cannot execute or satisfy this gate.
func TestShareUserUsesNonElevatedIdentityAndRevertsOnError(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var before windows.Token
	if e := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &before); e != windows.ERROR_NO_TOKEN {
		if e == nil {
			before.Close()
		}
		t.Fatalf("test thread must start without impersonation: %v", e)
	}
	user, release, err := shareUser()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	want := errors.New("callback failed")
	err = user(func() error {
		identity, e := shareTokenIdentity(windows.GetCurrentThreadToken())
		if e != nil {
			return e
		}
		owner, e := shareTokenIdentity(windows.GetCurrentProcessToken())
		if e != nil {
			return e
		}
		if e = validateShareIdentity(owner, identity); e != nil {
			return e
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("ordinary-user callback failed: %v", err)
	}
	var after windows.Token
	if e := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &after); e != windows.ERROR_NO_TOKEN {
		if e == nil {
			after.Close()
		}
		t.Fatalf("thread identity was not restored: %v", e)
	}
}
