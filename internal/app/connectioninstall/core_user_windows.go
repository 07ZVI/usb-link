//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"runtime"
)

// Explicit service binding is the sole source of user identity. Before logon,
// file sharing remains unavailable; SYSTEM is never the sharing user.
func coreShareUser(ownerSID string) (func(func() error) error, func(), error) {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0 || session == 0xffffffff {
		return nil, nil, fmt.Errorf("CORE_SHARE_USER_NOT_LOGGED_ON")
	}
	var user windows.Token
	if e := windows.WTSQueryUserToken(session, &user); e != nil {
		return nil, nil, fmt.Errorf("CORE_SHARE_USER_TOKEN_UNAVAILABLE")
	}
	defer user.Close()
	identity, e := shareTokenIdentity(user)
	if e != nil || validateShareIdentity(shareIdentity{SID: ownerSID, Session: session}, identity) != nil {
		return nil, nil, fmt.Errorf("CORE_SHARE_USER_IDENTITY_CHANGED")
	}
	var impersonation windows.Token
	if e = windows.DuplicateTokenEx(user, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); e != nil {
		return nil, nil, e
	}
	duplicate, e := shareTokenIdentity(impersonation)
	if e != nil || validateShareIdentity(identity, duplicate) != nil {
		impersonation.Close()
		return nil, nil, fmt.Errorf("CORE_SHARE_DUPLICATE_CHANGED")
	}
	level, e := shareTokenDWORD(impersonation, windows.TokenImpersonationLevel)
	if e != nil || level < windows.SecurityImpersonation {
		impersonation.Close()
		return nil, nil, fmt.Errorf("CORE_SHARE_IMPERSONATION_LEVEL_INVALID")
	}
	return func(f func() error) error {
		// The retained catalogue token is invalidated when its interactive session
		// changes. A different logged-in account never inherits this user's grants.
		if windows.WTSGetActiveConsoleSessionId() != session {
			return fmt.Errorf("CORE_SHARE_SESSION_CHANGED")
		}
		var current windows.Token
		if windows.WTSQueryUserToken(session, &current) != nil {
			return fmt.Errorf("CORE_SHARE_SESSION_TOKEN_UNAVAILABLE")
		}
		fresh, e := shareTokenIdentity(current)
		current.Close()
		if e != nil || validateShareIdentity(identity, fresh) != nil {
			return fmt.Errorf("CORE_SHARE_SESSION_IDENTITY_CHANGED")
		}
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if e = windows.SetThreadToken(nil, impersonation); e != nil {
			return e
		}
		defer func() {
			if windows.RevertToSelf() != nil {
				os.Exit(1)
			}
		}()
		return f()
	}, func() { impersonation.Close() }, nil
}
func sharedDirectoryOwnerSID() (string, error) {
	if sid, ok := BoundCoreOwnerSID(); ok {
		return sid, nil
	}
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return "", e
	}
	if u.User.Sid.String() == "S-1-5-18" {
		return "", fmt.Errorf("CORE_USER_BINDING_REQUIRED")
	}
	return u.User.Sid.String(), nil
}

// WithBoundCoreUser is for user-scope native operations such as DPAPI. It does
// not grant interactive consent and never falls back to SYSTEM's user profile.
func WithBoundCoreUser(f func() error) error {
	owner, bound := BoundCoreOwnerSID()
	self, e := os.Executable()
	if !bound || e != nil {
		return fmt.Errorf("CORE_USER_BINDING_REQUIRED")
	}
	if _, e = ActivateCoreOwner(self); e != nil {
		return e
	}
	run, release, e := coreShareUser(owner)
	if e != nil {
		return e
	}
	defer release()
	return run(f)
}

// Passing the explicit user token to SHGetKnownFolderPath avoids resolving the
// SYSTEM Desktop in Session0. No logged-in bound user means no desktop access.
func UserKnownFolderPath(folder *windows.KNOWNFOLDERID, flags uint32) (string, error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return "", e
	}
	if !u.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return windows.KnownFolderPath(folder, flags)
	}
	var path string
	e = WithBoundCoreUser(func() error {
		var token windows.Token
		if e := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, true, &token); e != nil {
			return e
		}
		defer token.Close()
		var e error
		path, e = token.KnownFolderPath(folder, flags)
		return e
	})
	return path, e
}
