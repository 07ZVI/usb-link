//go:build windows && amd64

package usbhost

import (
	"golang.org/x/sys/windows"
	"testing"
)

func TestRecreateOldJournalAllowsOnlyAdministratorSystemACL(t *testing.T) {
	for _, sddl := range []string{
		"O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)",
		"O:SYG:SYD:(A;ID;FA;;;SY)(A;ID;FA;;;BA)",
		"O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)",
	} {
		sd, e := windows.SecurityDescriptorFromString(sddl)
		if e != nil || !recreateJournalACLMatches(sd) {
			t.Fatalf("legitimate inherited/protected journal rejected: %s %v", sddl, e)
		}
	}
	for _, sddl := range []string{
		"O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;AU)",
		"O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;AU)",
		"O:WOG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)",
		"O:BAG:BAD:(A;IO;FA;;;SY)(A;IO;FA;;;BA)",
		"O:BAG:BAD:(A;;FR;;;SY)(A;;FA;;;BA)",
		"O:BAG:BAD:(D;;FA;;;SY)(A;;FA;;;BA)",
	} {
		sd, e := windows.SecurityDescriptorFromString(sddl)
		if e != nil {
			t.Fatal(e)
		}
		if recreateJournalACLMatches(sd) {
			t.Fatal("unproven journal ACL accepted", sddl)
		}
	}
	if recreateJournalACLMatches(nil) {
		t.Fatal("nil DACL accepted")
	}
}
