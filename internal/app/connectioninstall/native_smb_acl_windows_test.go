//go:build windows && amd64

package connectioninstall

import (
	"golang.org/x/sys/windows"
	"testing"
)

// These exercise Windows' descriptor parser without changing any file ACLs,
// shares, users or system policies. Cross-compilation is not execution proof.
func TestSMBRootDACLComparisonRetainsAccessAndProtection(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"D:(A;OICI;FA;;;SY)", "D:AI(A;OICI;FA;;;SY)", true},
		{"D:P(A;OICI;FA;;;SY)", "D:PAI(A;OICI;FA;;;SY)", true},
		{"D:(A;OICI;FA;;;SY)", "D:P(A;OICI;FA;;;SY)", false},
		{"D:(A;OICI;FA;;;SY)", "D:(A;OICI;FR;;;SY)", false},
		{"D:(A;OICI;FA;;;SY)", "D:(A;OI;FA;;;SY)", false},
		{"D:(A;OICI;FA;;;SY)", "D:(A;OICI;FA;;;BA)", false},
		{"D:(A;OICI;FA;;;SY)", "D:(D;OICI;FA;;;SY)", false},
		{"D:(A;;FA;;;SY)", "D:(A;;FA;;;SY)(A;;FA;;;BA)", false},
		{"D:NO_ACCESS_CONTROL", "D:", false},
		{"invalid", "invalid", false},
	} {
		if got := sameSMBRootDACL(tc.a, tc.b); got != tc.same {
			t.Fatalf("%q / %q: %t, want %t", tc.a, tc.b, got, tc.same)
		}
	}
}

func TestCompletedACLRestoreRetainsOnlyLocallyAcceptedBaseline(t *testing.T) {
	c := smbACLConfiguration{Roots: []smbACLReceipt{
		{ID: "000000000000000000000001", Before: "D:(A;;FA;;;SY)", After: "D:(A;;FA;;;SY)(A;;FR;;;BA)", AcceptedBaseline: true},
		{ID: "123456789012345678901234", Before: "D:(A;;FA;;;SY)", After: "D:(A;;FR;;;SY)"},
	}}
	c = completedSMBACLRestore(c, 1)
	if len(c.Roots) != 1 {
		t.Fatal("ordinary recovery receipt retained", c)
	}
	c = completedSMBACLRestore(c, 0)
	if len(c.Roots) != 1 || !c.Roots[0].Retained || c.Roots[0].After != c.Roots[0].Before {
		t.Fatal("locally approved baseline lost", c)
	}
}

func TestPendingNativeGuestShareApprovesOnlyJournaledDescriptors(t *testing.T) {
	s := nativeSMBShare{ID: "123456789012345678901234", Name: "USB-12345678", Path: `C:\Shared`, SID: "S-1-5-21-1-2-3-1001", GuestUpdate: true, NextGuestSID: "S-1-5-21-1-2-3-501"}
	for _, tc := range []struct {
		guest string
		owned bool
	}{{"", true}, {s.NextGuestSID, true}, {"S-1-5-21-1-2-3-1002", false}} {
		sd, e := nativeSD(s.SID, tc.guest)
		if e != nil {
			t.Fatal(e)
		}
		got := &nativeShare502{Name: windows.StringToUTF16Ptr(s.Name), Path: windows.StringToUTF16Ptr(s.Path), Remark: windows.StringToUTF16Ptr(nativeSMBMarker + s.ID), SD: sd}
		if ownedNativeShare(s, got) != tc.owned {
			t.Fatal("unapproved descriptor accepted", tc)
		}
		got.Path = windows.StringToUTF16Ptr(`C:\Other`)
		if ownedNativeShare(s, got) {
			t.Fatal("foreign path accepted by pending journal")
		}
	}
}

func TestNativeSMBAccessDescriptorsPreserveReadOnlyAndEmptyDACL(t *testing.T) {
	s := nativeSMBShare{SID: "S-1-5-21-11-22-33-1001", GuestSID: "S-1-5-21-11-22-33-501", AccountAccess: "read", GuestAccess: "none"}
	sd, e := nativeShareSD(s)
	if e != nil {
		t.Fatal(e)
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount != 1 {
		t.Fatal("read must have exactly one non-null grant", e)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if e = windows.GetAce(acl, 0, &ace); e != nil || ace.Mask != 0x1200a9 {
		t.Fatal("incorrect read mask", e)
	}
	s.AccountAccess = "none"
	sd, e = nativeShareSD(s)
	if e != nil {
		t.Fatal(e)
	}
	acl, _, e = sd.DACL()
	if e != nil || acl == nil || acl.AceCount != 0 {
		t.Fatal("deny-all must be an empty DACL, never null/full access", e)
	}
}

func TestNativeSMBEmptyShareACLRejectsNullAndUnprotectedAccess(t *testing.T) {
	want, e := windows.SecurityDescriptorFromString("D:P")
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		descriptor string
		allowed    bool
	}{
		{"D:P", true}, {"D:", false}, {"D:NO_ACCESS_CONTROL", false}, {"D:P(A;;FA;;;WD)", false},
	} {
		actual, e := windows.SecurityDescriptorFromString(tc.descriptor)
		if e != nil {
			t.Fatal(e)
		}
		if sameNativeSMBShareACL(actual, want) != tc.allowed {
			t.Fatal("incorrect deny-all ownership", tc)
		}
	}
}
