//go:build windows && amd64

package netconfig

// InspectSharedHostIdentity uses the same fresh native reads but returns only
// bounded metadata. Its output is an observation, never recovery authority.
func InspectSharedHostIdentity(index uint32) HostIdentityDiagnostic {
	t, d, _ := openVerifiedNativeHost(index)
	if t != nil {
		t.set.Close()
	}
	if d.PnPCount != nil && *d.PnPCount == 0 && d.Phase == "native_pnp_enumeration" {
		d.InstalledNodes = inspectInstalledHostNodes()
	}
	return d
}
