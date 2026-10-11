package ipadncm

import "testing"

func TestIPadCandidateStageOrder(t *testing.T) {
	defer SetIPadCandidateStage(0)
	for _, tc := range []struct {
		stage int
		want  CandidateFeatures
	}{
		{0, CandidateFeatures{}},
		{3, CandidateFeatures{PersistentGrouping: true}},
		{41, CandidateFeatures{PersistentGrouping: true, EventStartup: true}},
		{42, CandidateFeatures{PersistentGrouping: true, EventStartup: true, NativeConflict: true}},
		{43, CandidateFeatures{true, true, true, true}},
		{4, CandidateFeatures{true, true, true, true}},
	} {
		if !SetIPadCandidateStage(tc.stage) || IPadCandidateFeatures() != tc.want {
			t.Fatalf("stage %d: got %+v want %+v", tc.stage, IPadCandidateFeatures(), tc.want)
		}
	}
	before := IPadCandidateFeatures()
	for _, bad := range []int{-1, 1, 2, 5, 40, 44, 100} {
		if SetIPadCandidateStage(bad) || IPadCandidateFeatures() != before {
			t.Fatalf("unsupported stage %d accepted or altered features", bad)
		}
	}
}
