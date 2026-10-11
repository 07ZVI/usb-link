package connectioninstall

// A pending automatic installation cannot retain an authorization that was
// switched off and back on while its receipt notification was being shown.
func updateConsentValid(approved, automatic, debugEnabled, autoEnabled bool, captured, current uint64, sameAPI, usbConnected bool) bool {
	return approved && debugEnabled && sameAPI && usbConnected && (!automatic || (autoEnabled && captured == current))
}
