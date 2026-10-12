package connectioninstall

import (
	"strings"
	"testing"
)

func TestDeletedServiceReportedDisplayName(t *testing.T) {
	const description = "USB Link core: owned USB networking, local UI IPC; no interactive Session0 UI."
	// The returned Windows report has DisplayName USBLinkCore, not USB Link.
	for _, name := range []string{"USBLinkCore", "USB Link"} {
		if err := validateDeletedServiceMetadata(name, description, ""); err != nil {
			t.Fatalf("known legacy display name %q: %v", name, err)
		}
	}
	for _, tc := range []struct{ name, description, password, field string }{
		{"Unrelated", description, "", "displayName"},
		{"", description, "", "displayName"},
		{"USBLinkCore ", description, "", "displayName"},
		{"USBLinkCore", "", "", "description"},
		{"USBLinkCore", "different service", "", "description"},
		{"USBLinkCore", description, "do-not-export", "password"},
	} {
		err := validateDeletedServiceMetadata(tc.name, tc.description, tc.password)
		if err == nil || !strings.Contains(err.Error(), tc.field) || strings.Contains(err.Error(), "do-not-export") {
			t.Fatalf("expected field-specific rejection without password disclosure: %v", err)
		}
	}
}
