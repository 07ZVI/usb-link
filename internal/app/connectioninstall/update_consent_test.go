package connectioninstall

import "testing"

func TestUpdateConsentRevocation(t *testing.T) {
	for _, c := range []struct {
		name                                           string
		approved, automatic, debug, auto, sameAPI, usb bool
		current                                        uint64
		want                                           bool
	}{
		{"manual approved", true, false, true, false, true, true, 1, true},
		{"manual declined", false, false, true, false, true, true, 1, false},
		{"automatic", true, true, true, true, true, true, 1, true},
		{"unchecked", true, true, true, false, true, true, 1, false},
		{"off and on again", true, true, true, true, true, true, 3, false},
		{"debug disabled", true, true, false, true, true, true, 1, false},
		{"listener replaced", true, true, true, true, false, true, 1, false},
		{"USB removed", true, true, true, true, true, false, 1, false},
		{"notification failed", false, true, true, true, true, true, 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := updateConsentValid(c.approved, c.automatic, c.debug, c.auto, 1, c.current, c.sameAPI, c.usb); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}
