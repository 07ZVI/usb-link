package startupopt

import "testing"

func TestOptionsRejectMutationOfActiveOwner(t *testing.T) {
	if Enabled(NativeNetwork) || Enabled("unrecognized") {
		t.Fatal("experiments must start disabled")
	}
	if Configure([]string{"unrecognized"}) == nil || Enabled(NativeNetwork) {
		t.Fatal("unknown option must not configure anything")
	}
	if Configure([]string{NativeNetwork, NativeNetwork}) == nil {
		t.Fatal("duplicate option accepted")
	}
	if Configure([]string{NativeTask}) != nil || !Enabled(NativeTask) || Enabled(DADZero) {
		t.Fatal("independent selection failed")
	}
	if Configure([]string{DADZero}) == nil || !Enabled(NativeTask) || Enabled(DADZero) {
		t.Fatal("a live owner must not change options")
	}
	snapshot := Snapshot()
	snapshot[NativeTask] = false
	if !Enabled(NativeTask) {
		t.Fatal("external snapshot changed configuration")
	}
}

func TestCombinedLegacySelectionIsKnownAndIndependent(t *testing.T) {
	if !valid(CombinedLegacyNetwork) || valid("combined_legacy_network,user_input") || Enabled(CombinedLegacyNetwork) {
		t.Fatal("independent combined mode must be known but disabled")
	}
	if value, present := Snapshot()[CombinedLegacyNetwork]; !present || value {
		t.Fatal("missing default-disabled diagnostic selection")
	}
}
