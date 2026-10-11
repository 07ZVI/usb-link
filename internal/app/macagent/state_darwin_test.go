//go:build darwin

package macagent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestObservedLegacyLongStatusCanUpgradeWithoutUnboundedState(t *testing.T) {
	s := State{Product: product, BinarySHA: strings.Repeat("a", 64), LastStatus: strings.Repeat("x", 16426)}
	b, _ := json.Marshal(s)
	got, err := decodeState(b)
	if err != nil || len(got.LastStatus) != 1024 || got.BinarySHA != s.BinarySHA {
		t.Fatal(got, err)
	}
	s.Product = "foreign"
	b, _ = json.Marshal(s)
	if _, err = decodeState(b); err == nil {
		t.Fatal("foreign state accepted")
	}
	s.Product = product
	s.LastStatus = strings.Repeat("x", 65537)
	b, _ = json.Marshal(s)
	if _, err = decodeState(b); err == nil {
		t.Fatal("unbounded state accepted")
	}
	s.LastStatus = ""
	s.AddressProfile = "unknown"
	b, _ = json.Marshal(s)
	if _, err = decodeState(b); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestStatusTruncationPreservesUTF8(t *testing.T) {
	if got := boundedStatus(strings.Repeat("測", 1100)); len([]rune(got)) != 1024 || !json.Valid([]byte(`"`+got+`"`)) {
		t.Fatal("invalid UTF8 status")
	}
}
