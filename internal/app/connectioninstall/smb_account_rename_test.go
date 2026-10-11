package connectioninstall

import (
	"fmt"
	"testing"
)

func TestRenameRecoveryNeverAdoptsReusedWindowsNames(t *testing.T) {
	const owned = "S-1-5-21-1-2-3-1001"
	journal := smbAccountRename{From: "USBLinkShare", To: "共享", SID: owned}
	for _, tc := range []struct {
		label, receipt, sid, oldSID, newSID, want string
	}{
		{"before Windows change", journal.From, owned, owned, "", journal.From},
		{"after Windows change", journal.From, owned, "", owned, journal.To},
		{"after receipt save", journal.To, owned, "", owned, journal.To},
		{"destination occupied; original intact", journal.From, owned, owned, "foreign", journal.From},
		{"original name reused after rename", journal.From, owned, "foreign", owned, journal.To},
		{"both names reused", journal.From, owned, "foreign", "foreign", ""},
		{"updated receipt cannot roll back to original name", journal.To, owned, owned, "foreign", ""},
		{"journal belongs to different SID", journal.From, "foreign", owned, owned, ""},
		{"receipt has unrelated name", "OtherUser", owned, owned, owned, ""},
	} {
		t.Run(tc.label, func(t *testing.T) {
			calls := 0
			got, err := resolveSMBAccountRename(tc.receipt, tc.sid, journal, func(name, sid string) error {
				calls++
				actual := tc.oldSID
				if name == journal.To {
					actual = tc.newSID
				}
				if actual == "" || actual != sid {
					return fmt.Errorf("missing or foreign ownership")
				}
				return nil
			})
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
			if (tc.sid != owned || tc.receipt == "OtherUser") && calls != 0 {
				t.Fatal("invalid receipt must not query accounts")
			}
		})
	}
}
