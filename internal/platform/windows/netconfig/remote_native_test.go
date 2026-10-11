package netconfig

import "testing"

func TestLegacyCleanupRejectsAdditionalIdentityConstraints(t *testing.T) {
	for _, parts := range [][]string{nil, {}, {"NULL"}, {"S:"}} {
		if !unrestrictedLegacyConstraint(parts, false) {
			t.Fatal("empty rejected", parts)
		}
	}
	for _, parts := range [][]string{{"S:Any"}, {"S:S-1-5-21-owner"}, {"S:policy-app-tag"}, {"N:0"}, {"B:false"}, {"NULL", "S:"}} {
		if unrestrictedLegacyConstraint(parts, false) {
			t.Fatal("changed identity silently adopted", parts)
		}
	}
	if !unrestrictedLegacyConstraint([]string{"S:Any"}, true) || unrestrictedLegacyConstraint([]string{"S:other-package"}, true) {
		t.Fatal("filter wildcard contract changed")
	}
}
