package interfaceconfig

// PersistentOriginalSnapshot is a local protected-record observation, never
// live interface authorization. ImmutableScope stays at first capture even
// when an owned factory transaction publishes a separate current mapping.
type PersistentOriginalSnapshot struct {
	ImmutableScope           Scope
	SHA256                   string
	OriginalMTU              uint32
	DesiredMTU               uint32
	AddressAbsent            bool
	Address                  string
	Prefix                   uint32
	NetworkGUID              string
	OriginalCategory         uint32
	AppliedValidLifetime     string
	AppliedPreferredLifetime string
}

func originalSnapshot(v persistentOriginal) (PersistentOriginalSnapshot, bool) {
	if validateScope(v.Scope) != nil || v.AppliedAddress == nil || v.Profile == nil {
		return PersistentOriginalSnapshot{}, false
	}
	return PersistentOriginalSnapshot{ImmutableScope: v.Scope, SHA256: persistentDigest(v), OriginalMTU: v.OriginalMTU, DesiredMTU: v.DesiredMTU, AddressAbsent: v.AddressAbsent, Address: v.Address, Prefix: v.Prefix, NetworkGUID: v.Profile.NetworkGUID, OriginalCategory: uint32(v.Profile.Category), AppliedValidLifetime: v.AppliedAddress.ValidLifetime, AppliedPreferredLifetime: v.AppliedAddress.PreferredLifetime}, true
}
