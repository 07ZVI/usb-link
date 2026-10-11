package connectioninstall

import "testing"

func TestSMBFilesystemACLModeKeepsNullSeparateFromDenyAllEmptyACL(t *testing.T) {
	for _, v := range []struct {
		persistent, present, null bool
		mode                      string
	}{
		{false, false, true, "filesystem-no-acl"},
		{false, true, false, "filesystem-no-acl"},
		{true, false, true, "already-permissive"},
		{true, true, true, "already-permissive"},
		{true, true, false, "managed"}, // also covers allocated empty, zero-ACE deny-all ACLs
	} {
		if got := smbDACLMode(v.persistent, v.present, v.null); got != v.mode {
			t.Fatalf("%+v: %s", v, got)
		}
	}
}
