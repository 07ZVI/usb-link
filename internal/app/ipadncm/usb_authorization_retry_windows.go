//go:build windows && amd64

package ipadncm

func preflightFactsOf(s Snapshot) preflightFacts {
	f := preflightFacts{SnapshotError: s.Error, DeviceCount: len(s.Devices), RootUnique: exactIPadRoot(s) != ""}
	if len(s.Devices) == 1 {
		d := s.Devices[0]
		f.DeviceErrors = append([]string(nil), d.Errors...)
		f.SerialStatus, f.ProductStatus = d.USBSerialReadStatus, d.USBProductReadStatus
		f.Configuration, f.DescriptorRead = d.CurrentConfiguration, true
	}
	return f
}

// Launcher entry points: the final error for an attempt whose first
// authorization (or a later re-verification) failed.
func AuthorizationFailureError(fallback string) string {
	return authorizationFailureError(authorizationOutcomeSnapshot(), fallback)
}
func ModeFailureError(status string) string {
	return modeFailureError(status, authorizationOutcomeSnapshot())
}
