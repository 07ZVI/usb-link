package netconfig

// A rejected or changing retained proof never falls through to address creation.
// The legacy entry invokes create exactly once and never asks for retained proof.
func runMacAddressPhase(retained bool, verifyRetained, create func() error) error {
	if retained {
		return verifyRetained()
	}
	return create()
}
