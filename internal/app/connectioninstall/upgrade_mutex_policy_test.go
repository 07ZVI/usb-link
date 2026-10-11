package connectioninstall

import (
	"strings"
	"testing"
)

func TestUpgradeMutexGenericRightsAndEffectiveRights(t *testing.T) {
	// The security manager may return effective kernel rights even when the
	// creating application's SDDL used GA. Both descriptors grant precisely
	// the same rights; byte-comparing their ACEs was the .74 rejection boundary.
	for _, mask := range []uint32{genericAllAccess, mutexAllAccess, genericAllAccess | mutexAllAccess} {
		entries := []mutexACE{{Mask: mask, Principal: "system"}, {Mask: mutexAllAccess, Principal: "administrators"}}
		for _, owner := range []string{"system", "administrators", "process_user"} {
			if err := validateMutexPolicy(owner, true, entries); err != nil {
				t.Fatalf("equivalent kernel access rejected mask=%x owner=%s: %v", mask, owner, err)
			}
		}
	}
}

func TestUpgradeMutexEffectivePolicyRejectsBroadenedOrUnknownSecurity(t *testing.T) {
	base := []mutexACE{{Mask: mutexAllAccess, Principal: "system"}, {Mask: mutexAllAccess, Principal: "administrators"}}
	cases := []struct {
		name, owner, reason string
		present             bool
		change              func([]mutexACE) []mutexACE
	}{
		{"foreign owner", "other", "owner", true, nil},
		{"missing owner", "", "owner", true, nil},
		{"null DACL", "administrators", "dacl_null", false, nil},
		{"empty DACL", "administrators", "ace_count", true, func(a []mutexACE) []mutexACE { return nil }},
		{"extra user", "administrators", "ace_count", true, func(a []mutexACE) []mutexACE {
			return append(a, mutexACE{Mask: mutexAllAccess, Principal: "process_user"})
		}},
		{"replace system", "administrators", "ace_principal", true, func(a []mutexACE) []mutexACE { a[0].Principal = "process_user"; return a }},
		{"duplicate admin", "administrators", "ace_principal", true, func(a []mutexACE) []mutexACE { a[0].Principal = "administrators"; return a }},
		{"inherited", "administrators", "inheritance", true, func(a []mutexACE) []mutexACE { a[0].Flags = 16; return a }},
		{"inheritable", "administrators", "inheritance", true, func(a []mutexACE) []mutexACE { a[0].Flags = 2; return a }},
		{"deny", "administrators", "ace_type", true, func(a []mutexACE) []mutexACE { a[0].Type = 1; return a }},
		{"callback", "administrators", "ace_type", true, func(a []mutexACE) []mutexACE { a[0].Type = 9; return a }},
		{"missing synchronize", "administrators", "ace_mask", true, func(a []mutexACE) []mutexACE { a[0].Mask &^= 0x100000; return a }},
		{"unknown object right", "administrators", "ace_mask", true, func(a []mutexACE) []mutexACE { a[0].Mask |= 2; return a }},
		{"generic extra right", "administrators", "ace_mask", true, func(a []mutexACE) []mutexACE { a[0].Mask = genericAllAccess | 2; return a }},
		{"unmapped generic read", "administrators", "ace_mask", true, func(a []mutexACE) []mutexACE { a[0].Mask |= 0x80000000; return a }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := append([]mutexACE(nil), base...)
			if c.change != nil {
				a = c.change(a)
			}
			if err := validateMutexPolicy(c.owner, c.present, a); err == nil || !strings.Contains(err.Error(), c.reason) {
				t.Fatalf("unsafe descriptor accepted or wrong diagnosis: %v", err)
			}
		})
	}
}
