package ipadncm

import "sync"

// CandidateFeatures separates U1 connection work from I7 isolation. All fields
// start false. The integrator advances this fixed stage only after the preceding
// hardware acceptance; no UI or environment variable can bypass that gate.
type CandidateFeatures struct {
	PersistentGrouping bool
	EventStartup       bool
	NativeConflict     bool
	EarlyDHCP          bool
}

var candidateFeatureState struct {
	sync.Mutex
	stage int
}

// Stages: 3 persistent grouping; 41 event startup; 42 native conflict query;
// 43 early DHCP. Stage 4 aliases 43. Returning to 0 requires the integrator
// to restore persistent grouping first. This setter never performs restoration.
func SetIPadCandidateStage(stage int) bool {
	if stage != 0 && stage != 3 && stage != 4 && stage != 41 && stage != 42 && stage != 43 {
		return false
	}
	candidateFeatureState.Lock()
	candidateFeatureState.stage = stage
	candidateFeatureState.Unlock()
	return true
}
func IPadCandidateFeatures() CandidateFeatures {
	// A separate, explicit one-attempt experiment supplies a fresh native scope.
	// It changes no accepted stage, saved choice or dual-mode proof.
	if unpairedFeatureLease.Load() || unpairedProductFeatures.Load() || simplifiedNetworkFeatures.Load() {
		return CandidateFeatures{true, true, true, true}
	}
	candidateFeatureState.Lock()
	stage := candidateFeatureState.stage
	candidateFeatureState.Unlock()
	return CandidateFeatures{stage != 0, stage == 4 || stage >= 41, stage == 4 || stage >= 42, stage == 4 || stage >= 43}
}
