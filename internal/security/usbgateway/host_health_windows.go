//go:build windows && amd64

package usbgateway

// The supervisor checks the same fixed base and core permits used by Attach.
// External filter deletion must not leave a generation published as ready.
func (m *Manager) VerifiedSharedHostAttachment(luid uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.links[luid]
	if a == nil || a.peer != "" || luid == 0 || luid != sharedHostLUID.Load() {
		return false
	}
	base, e := BasePolicy(luid)
	if e != nil {
		return false
	}
	local, e := LocalDeliveryPolicy(luid, "")
	if e != nil {
		return false
	}
	base = append(base, local...)
	smb, e := NativeSMBPolicy(luid, "")
	if e != nil {
		return false
	}
	base = append(base, smb...)
	if len(a.keys) < len(base) || len(a.core) == 0 {
		return false
	}
	for i, spec := range base {
		if verifyFilter(m.engine, a.keys[i], a.sub, spec) != nil {
			return false
		}
	}
	for path := range a.core {
		specs, e := PermitPolicy(luid, path)
		keys := a.permit[path]
		if e != nil || len(keys) != len(specs) {
			return false
		}
		for i, spec := range specs {
			if verifyFilter(m.engine, keys[i], a.sub, spec) != nil {
				return false
			}
		}
	}
	return true
}
