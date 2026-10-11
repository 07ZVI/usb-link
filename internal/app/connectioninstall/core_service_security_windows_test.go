//go:build windows && amd64

package connectioninstall

import (
	"golang.org/x/sys/windows"
	"testing"
)

func TestCoreFileSecurityPreservesInheritedReadButRejectsForeignWrite(t *testing.T) {
	for name, sddl := range map[string]string{
		"protected":           "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
		"installed_inherited": "O:BAG:BAD:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)",
	} {
		t.Run(name, func(t *testing.T) {
			sd, e := windows.SecurityDescriptorFromString(sddl)
			if e != nil || !coreFileACLValid(sd) {
				t.Fatalf("valid source security rejected: %v", e)
			}
		})
	}
	for name, sddl := range map[string]string{
		"foreign_owner":     "O:BUG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
		"foreign_write":     "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)",
		"missing_system":    "O:BAG:BAD:P(A;;FA;;;BA)",
		"unknown_principal": "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)",
		"null_dacl":         "O:BAG:BAD:NO_ACCESS_CONTROL",
		"deny_ace":          "O:BAG:BAD:P(D;;FW;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)",
	} {
		t.Run(name, func(t *testing.T) {
			sd, e := windows.SecurityDescriptorFromString(sddl)
			if e != nil {
				t.Fatal(e)
			}
			if coreFileACLValid(sd) {
				t.Fatal("unsafe source security accepted")
			}
		})
	}
}
