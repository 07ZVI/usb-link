package ipadncm

// CandidateFeatures selects the connection features that need a fresh native
// scope. The staged candidate controller that once advanced them by hand is
// gone; the simplified USB network enables all of them as one set.
type CandidateFeatures struct {
	PersistentGrouping bool
	EventStartup       bool
	NativeConflict     bool
	EarlyDHCP          bool
}

func IPadCandidateFeatures() CandidateFeatures {
	if simplifiedNetworkFeatures.Load() {
		return CandidateFeatures{true, true, true, true}
	}
	return CandidateFeatures{}
}
