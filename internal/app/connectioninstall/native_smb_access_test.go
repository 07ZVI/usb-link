package connectioninstall

import (
	"strconv"
	"strings"
	"testing"
)

func TestSMBShareAccessRequiresSelectedIdentityAndNTFSJournal(t *testing.T) {
	for _, tc := range []struct{ persistent, selected, journal, allowed bool }{
		{true, true, true, true}, {true, true, false, false}, {true, false, true, false},
		{false, true, false, true}, {false, true, true, true}, {false, false, true, false}, {false, false, false, false},
	} {
		if verifiedSMBAccessRoot(tc.persistent, tc.selected, tc.journal) != tc.allowed {
			t.Fatalf("unexpected root authority: %+v", tc)
		}
	}
}

func TestSMBAccessMasksRestrictWritesAndAdministrativeRights(t *testing.T) {
	read, _ := smbAccessMask("read")
	modify, _ := smbAccessMask("modify")
	r, _ := strconv.ParseUint(strings.TrimPrefix(read, "0x"), 16, 32)
	m, _ := strconv.ParseUint(strings.TrimPrefix(modify, "0x"), 16, 32)
	const mutation = 0x2 | 0x4 | 0x10 | 0x100 | 0x10000
	const administration = 0x40000 | 0x80000
	if r&mutation != 0 || r&administration != 0 {
		t.Fatal("read grants mutation or ACL ownership")
	}
	if m&mutation != mutation || m&administration != 0 || m&r != r {
		t.Fatal("modify must allow file changes and reads without ACL administration")
	}
	if mask, e := smbAccessMask("none"); e != nil || mask != "" {
		t.Fatal("denied identity receives grant")
	}
	if _, e := smbAccessMask("full"); e == nil {
		t.Fatal("unrecognized access accepted")
	}
	if mask, e := smbAccessMask(""); e != nil || mask != "FA" {
		t.Fatal("legacy receipt changed")
	}
}
