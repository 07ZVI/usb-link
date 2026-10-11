//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"errors"
	"strings"
)

// WithPersistentHostFactoryProof keeps the protected configuration mutex across
// full fresh Store/native/active proofs and the caller's fixed host checkpoint.
// verifyOwner must prove its private held factory and protected pre-call/mapped
// transaction. Neither callback may re-enter interfaceconfig or change Store.
// A failed post-check retains the caller's unknown transaction; it is not Ready.
func WithPersistentHostFactoryProof(ctx context.Context, dir string, s Scope, immutableSHA, mode string, created int64, owner func() error, profile ProfileOps, commit func(ActiveOwnership) error) error {
	if s.Role != "host" || validateScope(s) != nil || len(immutableSHA) != 64 || strings.Trim(immutableSHA, "0123456789abcdef") != "" || owner == nil || commit == nil || profile.Read == nil || !PersistentEnabled() || (mode != "persistent" && mode != "legacy") || (mode == "persistent" && created != 0) || (mode == "legacy" && created <= 0) {
		return errors.New("USB_PERSISTENT_FACTORY_PROOF_INVALID")
	}
	finish, e := lockConfig()
	if e != nil {
		return e
	}
	defer finish()
	original := func() error {
		r, found, e := readConfigReceiptFile(dir)
		if e != nil || !found || r.RestoreRequested {
			return errors.New("USB_PERSISTENT_FACTORY_ORIGINAL_UNPROVEN")
		}
		for _, v := range r.Persistent {
			if v.Scope.Role == "host" {
				sn, ok := originalSnapshot(v)
				if ok && sn.SHA256 == immutableSHA && strings.EqualFold(v.Scope.GUID, s.GUID) {
					return nil
				}
				return errors.New("USB_PERSISTENT_FACTORY_ORIGINAL_CHANGED")
			}
		}
		return errors.New("USB_PERSISTENT_FACTORY_ORIGINAL_UNPROVEN")
	}
	return runFactoryProofCheckpoint(s, immutableSHA, mode, created, original, func() (ActiveOwnership, error) {
		return verifyPersistentModeUnlocked(ctx, dir, s, owner, profile, mode, created)
	}, func() error { return fresh(ctx, s, owner) }, commit)
}
