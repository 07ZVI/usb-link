package ipadsession

type AddressIdentity struct {
	LUID                               uint64
	Index                              uint32
	Prefix, PrefixOrigin, SuffixOrigin uint32
	ValidLifetime, PreferredLifetime   uint32
	CreatedAt                          int64
}

// A restarted adapter, recreated address, different origin or indefinite
// lifetime must never be deleted as ours. The bounded intent window only
// covers a crash between creation and the durable timestamp checkpoint.
func OwnedAddress(p Plan, a AddressIdentity) bool {
	if !p.Valid() || a.LUID != p.LUID || a.Index != p.Index || a.Prefix != uint32(p.AddressPrefix()) || a.PrefixOrigin != 1 || a.SuffixOrigin != 1 || a.ValidLifetime > p.AddressLifetime() || a.PreferredLifetime > p.AddressLifetime() {
		return false
	}
	if p.Version == 6 && p.AddressMode == "persistent" && (a.ValidLifetime != ^uint32(0) || a.PreferredLifetime != ^uint32(0)) {
		return false
	}
	if p.CreatedAt != 0 {
		return a.CreatedAt == p.CreatedAt
	}
	return a.CreatedAt >= p.PlannedAt && a.CreatedAt-p.PlannedAt <= 150000000
}
