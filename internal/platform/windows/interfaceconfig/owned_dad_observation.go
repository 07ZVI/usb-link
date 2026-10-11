package interfaceconfig

// Read-only telemetry deliberately omits the private node, USB root, driver,
// descriptor serial and file paths. No field grants mutation/recovery authority.
type OwnedDADObservation struct {
	ObservationOnly      bool    `json:"observation_only"`
	Scope                string  `json:"scope"`
	Role                 string  `json:"role"`
	GUID                 string  `json:"guid"`
	LUID                 uint64  `json:"luid"`
	OriginalIndex        uint32  `json:"original_index"`
	OriginalDadTransmits uint32  `json:"original_dad_transmits"`
	CurrentIndex         *uint32 `json:"current_index"`
	CurrentLUID          *uint64 `json:"current_luid"`
	CurrentDadTransmits  *uint32 `json:"current_dad_transmits"`
	Code                 string  `json:"code"`
}

func ownedDADObservation(o ownedDADOriginal) OwnedDADObservation {
	return OwnedDADObservation{ObservationOnly: true, Scope: "MAPPING_READ_ONLY_NOT_OWNERSHIP", Role: o.Identity.Scope.Role, GUID: o.Identity.Scope.GUID, LUID: o.Identity.Scope.LUID, OriginalIndex: o.Identity.Scope.Index, OriginalDadTransmits: o.Original, Code: "NATIVE_UNOBSERVED"}
}
