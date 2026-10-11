package ipadncm

import "testing"

func TestStartupIdentityRequiresSuccessfulSameRunModeEvidence(t *testing.T) {
	for _, tc := range []struct {
		product, err, status string
		active, want         bool
	}{
		{"iPad13,16", "", "NCM_DESCRIPTORS_AFTER_REQUEST", true, true},
		{"iPad13,16", "", "NCM_DESCRIPTORS_PRESENT", true, true},
		{"", "NEED_ONE_USB_APPLE_COMMUNICATION_DEVICE", "NCM_DESCRIPTORS_PRESENT", true, false},
		{"iPhone16,1", "", "NCM_DESCRIPTORS_PRESENT", true, false},
		{"iPad13,16", "PRODUCT_METADATA_QUERY_FAILED", "NCM_DESCRIPTORS_PRESENT", true, false},
		{"iPad13,16", "", "SET_ACKNOWLEDGED", true, false},
		{"iPad13,16", "", "NCM_DESCRIPTORS_AFTER_REQUEST", false, false},
	} {
		if got := startupModeIdentity(tc.product, tc.err, tc.status, tc.active); got != tc.want {
			t.Fatalf("%+v: got %v", tc, got)
		}
	}
}
