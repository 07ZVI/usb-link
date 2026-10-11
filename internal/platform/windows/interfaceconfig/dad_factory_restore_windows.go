//go:build windows && amd64

package interfaceconfig

import "context"

// RestoreDADZeroForOwnedFactoryForRestore consumes a DAD original only within
// an explicit uninstall restoring transaction. It must run before restoring
// and consuming the persistent Store original. The callback receives the exact
// recorded DAD scope and must prove its old LUID against the protected source,
// the original journal/Store SHA, the durable restore_mapped transaction, the
// same typed native instance and the held official returned factory handle.
// A new LUID is permitted only by that factory proof, never by a same-GUID
// observation. This entry point neither publishes network readiness nor
// applies new settings. Missing/changed originals retain their obligation.
func RestoreDADZeroForOwnedFactoryForRestore(ctx context.Context, dir string, original, current Scope, persistentSHA string, verifyRestoringFactory func(Scope) error) error {
	return restoreDADZeroForOwnedMapping(ctx, dir, original, current, persistentSHA, true, verifyRestoringFactory)
}
