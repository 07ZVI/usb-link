//go:build windows && amd64

package usbhost

import (
	"golang.org/x/sys/windows"
	"testing"
)

// This fixture is compiled on macOS, not executed there. On Windows it checks
// the security-descriptor contract without creating a file or changing ACLs.
func TestRemovalProtectedOwnerAndACL(t *testing.T) {
	expected, e := windows.SecurityDescriptorFromString(removalFileSDDL)
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{removalFileSDDL, "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"} {
		actual, e := windows.SecurityDescriptorFromString(s)
		if e != nil || !removalACLMatches(actual, expected) {
			t.Fatal("system/admin owner denied", e)
		}
	}
	for _, s := range []string{
		"O:BUG:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)",
		"O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)",
		"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)",
		"O:BAG:BAD:P(A;;FR;;;SY)(A;;FA;;;BA)",
	} {
		actual, e := windows.SecurityDescriptorFromString(s)
		if e != nil {
			t.Fatal(e)
		}
		if removalACLMatches(actual, expected) {
			t.Fatal("unexpected owner/ACL accepted", s)
		}
	}
}
