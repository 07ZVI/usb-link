package ipadncm

import (
	"reflect"
	"strings"
	"testing"
)

func TestUnpairedPairLeavesOnlyExactDescriptorNames(t *testing.T) {
	want := []string{"0123456789abcdef0123201e.plist", "01234567-89abcdef0123201e.plist"}
	for _, serial := range []string{"0123456789ABCDEF0123201E", "01234567-89abcdef0123201e"} {
		if got := unpairedPairLeaves(serial); !reflect.DeepEqual(got, want) {
			t.Fatalf("unexpected exact names: %v", got)
		}
	}
	for _, invalid := range []string{"201e", "../0123456789abcdef0123201e", "SystemConfiguration", "01234567/89abcdef0123201e", "0123456789abcdef0123201e.plist", " 0123456789abcdef0123201e", strings.Repeat("g", 24), "012345678-9abcdef0123201e"} {
		if got := unpairedPairLeaves(invalid); got != nil {
			t.Fatalf("suffix or arbitrary path admitted: %q", invalid)
		}
	}
	if got := unpairedPairLeaves(strings.Repeat("a", 40)); !reflect.DeepEqual(got, []string{strings.Repeat("a", 40) + ".plist"}) {
		t.Fatal("legacy exact name rejected")
	}
}
