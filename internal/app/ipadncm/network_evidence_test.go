package ipadncm

import "testing"

func TestNetworkBindingRejectsOtherClassAndUnstartedNodes(t *testing.T) {
	key := `{4D36E972-E325-11CE-BFC1-08002BE10318}\0001`
	guid := `{01234567-89AB-CDEF-0123-456789ABCDEF}`
	if value, ok := canonicalNetworkBinding(true, key, guid); !ok || value != "{01234567-89ab-cdef-0123-456789abcdef}" {
		t.Fatal(value, ok)
	}
	for _, tc := range []struct {
		started   bool
		key, guid string
	}{
		{false, key, guid}, {true, key + `\subkey`, guid}, {true, `{88BAE032-5A81-49F0-BC3D-A4FF138216D6}\0001`, guid},
		{true, key, ""}, {true, key, "{00000000-0000-0000-0000-000000000000}"}, {true, key, guid + "extra"},
	} {
		if _, ok := canonicalNetworkBinding(tc.started, tc.key, tc.guid); ok {
			t.Fatalf("invalid network binding: %+v", tc)
		}
	}
}
func TestPassiveCountersCannotCombineReplacementOrReset(t *testing.T) {
	in, out, ok := passiveCounterDelta("one", "one", 100, 200, 120, 240)
	if !ok || in != 20 || out != 40 {
		t.Fatal(in, out, ok)
	}
	for _, tc := range []struct {
		old, next string
		in, out   uint64
	}{
		{"one", "two", 120, 240}, {"", "", 120, 240}, {"one", "one", 99, 240}, {"one", "one", 120, 199},
	} {
		if _, _, ok := passiveCounterDelta(tc.old, tc.next, 100, 200, tc.in, tc.out); ok {
			t.Fatalf("replacement/reset counted: %+v", tc)
		}
	}
}
