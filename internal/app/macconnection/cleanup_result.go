package macconnection

type macCleanupResult struct {
	RecoveryError error
	MTUError      error
}

// MTU recovery is independent of the session journal and must still run when
// journal recovery fails. Neither obligation may be omitted from confirmation.
func runMacCleanup(recoverSession, restoreMTU func() error) macCleanupResult {
	return macCleanupResult{RecoveryError: recoverSession(), MTUError: restoreMTU()}
}

func (r macCleanupResult) confirmed() bool { return r.RecoveryError == nil && r.MTUError == nil }
