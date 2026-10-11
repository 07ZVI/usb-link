package connectioninstall

import "testing"

func TestShareIdentityRejectsElevatedOtherUserAndOtherSession(t *testing.T) {
	owner := shareIdentity{"S-1-5-21-1-1001", 2, true}
	for _, tc := range []struct {
		candidate shareIdentity
		allowed   bool
	}{
		{shareIdentity{owner.SID, 2, false}, true},
		{shareIdentity{owner.SID, 2, true}, false},
		{shareIdentity{"S-1-5-21-1-1002", 2, false}, false},
		{shareIdentity{owner.SID, 3, false}, false},
		{shareIdentity{"", 2, false}, false},
	} {
		if (validateShareIdentity(owner, tc.candidate) == nil) != tc.allowed {
			t.Fatalf("incorrect share boundary: %+v", tc)
		}
	}
}
