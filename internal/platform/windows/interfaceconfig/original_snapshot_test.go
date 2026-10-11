package interfaceconfig

import "testing"

func TestOriginalSnapshotKeepsImmutableCompleteBaseline(t *testing.T) {
	v := persistentOriginal{Scope: Scope{"host", HostGUID, 7, 9}, OriginalMTU: 9000, DesiredMTU: 1500, AddressAbsent: true, Address: "10.6.9.1", Prefix: 32, Profile: &profileOriginal{MacGUID, 0}, AppliedAddress: &addressBaseline{"infinite", "infinite"}}
	s, ok := originalSnapshot(v)
	if !ok || s.ImmutableScope != v.Scope || s.OriginalMTU != 9000 || s.SHA256 != persistentDigest(v) || s.OriginalCategory != 0 || s.AppliedValidLifetime != "infinite" {
		t.Fatal(s, ok)
	}
	other := v
	other.Scope.LUID = 10
	o, _ := originalSnapshot(other)
	if o.SHA256 == s.SHA256 {
		t.Fatal("mutable mapping must not silently share original digest")
	}
	v.Profile = nil
	if _, ok = originalSnapshot(v); ok {
		t.Fatal("partial original accepted")
	}
}
