package ipadeasy

// An existing I7 owner proves its scope before touching a new cold-attachment
// portable node. Non-I7 preparation retains its original prepare/ensure order.
func PrepareWithNetworkOnly(active bool, admit, ensure, prepare func() string) string {
	if active {
		if err := admit(); err != "" {
			return err
		}
		if err := ensure(); err != "" {
			return err
		}
	}
	if err := prepare(); err != "" {
		return err
	}
	return ensure()
}

// Re-enumeration may replace portable nodes. Never mutate after a failed mode
// or unconfirmed service restoration, and never start networking on failed I7.
func VerifyNetworkOnlyAfterMode(active bool, mode ModeOutcome, admitAndEnsure func() string) ModeOutcome {
	if active && mode.Ready && mode.Error == "" && (!mode.PauseAttempted || mode.Restored) {
		mode.Error = admitAndEnsure()
	}
	return mode
}

// Grouping reactivation runs inside a saved transaction. Reject unresolved
// service/mode outcomes before touching portable nodes; an isolation error must
// return through Activate so the transaction restores instead of observing or
// starting networking. Ordinary non-I7 outcomes retain their previous errors.
func CompleteGroupingModeWithNetworkOnly(active bool, mode ModeOutcome, admitAndEnsure func() string) string {
	if mode.PauseAttempted && !mode.Restored {
		return "GROUPING_MODE_APPLE_SERVICE_RESTORE_UNCONFIRMED"
	}
	if mode.Error != "" {
		return mode.Error
	}
	if !mode.Ready {
		return "GROUPING_MODE_NCM_UNCONFIRMED"
	}
	return VerifyNetworkOnlyAfterMode(active, mode, admitAndEnsure).Error
}
