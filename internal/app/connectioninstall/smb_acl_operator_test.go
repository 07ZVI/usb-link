package connectioninstall

import "testing"

func TestSMBACLMutationRequiresBoundServiceOrSameDesktopAdministrator(t *testing.T) {
	desktop := shareIdentity{SID: "S-1-5-21-1-1001", Session: 2}
	for _, tc := range []struct {
		operator shareIdentity
		bound    string
		allowed  bool
	}{
		{shareIdentity{SID: "S-1-5-18", Session: 0}, desktop.SID, true},
		{shareIdentity{SID: "S-1-5-18", Session: 0}, "", false},
		{shareIdentity{SID: "S-1-5-18", Session: 0}, "S-1-5-21-1-1002", false},
		{shareIdentity{SID: "S-1-5-18", Session: 2}, desktop.SID, false},
		{shareIdentity{SID: desktop.SID, Session: 2, Elevated: true}, "", true},
		{shareIdentity{SID: desktop.SID, Session: 2, Elevated: false}, "", false},
		{shareIdentity{SID: "S-1-5-21-1-1002", Session: 2, Elevated: true}, "", false},
		{shareIdentity{SID: desktop.SID, Session: 3, Elevated: true}, "", false},
	} {
		if got := validateSMBACLAdministrator(tc.operator, desktop, tc.bound) == nil; got != tc.allowed {
			t.Fatalf("operator=%+v bound=%q allowed=%t want=%t", tc.operator, tc.bound, got, tc.allowed)
		}
	}
	for _, bad := range []shareIdentity{{}, {SID: desktop.SID, Session: 0}, {SID: desktop.SID, Session: 2, Elevated: true}} {
		if validateSMBACLAdministrator(shareIdentity{SID: "S-1-5-18"}, bad, bad.SID) == nil {
			t.Fatalf("invalid desktop admitted: %+v", bad)
		}
	}
}
