package netconfig

import (
	"errors"
	"maps"
	"testing"
)

func TestNativeRuleCleanupCompleteEnabledOrDisabledOnly(t *testing.T) {
	spec, good := firewallPolicyFixture()
	for _, enabled := range []string{"N:1", "N:2"} {
		got := maps.Clone(good)
		got["/Enabled"] = []string{enabled}
		reads, owners := 0, 0
		hash, err := verifyNativeRuleCleanup(spec, "", func() (firewallConstraints, error) { reads++; return got, nil }, func() error { owners++; return nil })
		if err != nil || hash == "" || reads != 2 || owners != 3 {
			t.Fatalf("incomplete cleanup proof %v %d/%d", err, reads, owners)
		}
	}
	for _, value := range [][]string{nil, {"NULL"}, {"S:1"}, {"N:0"}, {"N:1", "N:1"}} {
		got := maps.Clone(good)
		got["/Enabled"] = value
		if hash, err := verifyNativeRuleCleanup(spec, "", func() (firewallConstraints, error) { return got, nil }, func() error { return nil }); err == nil || hash != "" {
			t.Fatal("unknown Enabled authorized cleanup")
		}
	}
	for field := range good {
		for _, enabled := range []string{"N:1", "N:2"} {
			got := maps.Clone(good)
			got["/Enabled"] = []string{enabled}
			delete(got, field)
			if _, err := verifyNativeRuleCleanup(spec, "", func() (firewallConstraints, error) { return got, nil }, func() error { return nil }); err == nil {
				t.Fatalf("partial rule authorized %s/%s", field, enabled)
			}
			got[field] = []string{"S:foreign"}
			if _, err := verifyNativeRuleCleanup(spec, "", func() (firewallConstraints, error) { return got, nil }, func() error { return nil }); err == nil {
				t.Fatalf("changed rule authorized %s/%s", field, enabled)
			}
		}
	}
	if _, err := verifyNativeRuleCleanup(spec, "", func() (firewallConstraints, error) { return good, nil }, nil); err == nil {
		t.Fatal("owner missing authorized cleanup")
	}
}

func TestNativeRuleCleanupPreflightsAllBeforeDelete(t *testing.T) {
	spec, good := firewallPolicyFixture()
	specs := make([]nativeRuleSpec, 5)
	rules := map[string]firewallConstraints{}
	for i, name := range []string{"one", "two", "three", "four", "five"} {
		s := spec
		s.Name = name
		specs[i] = s
		g := maps.Clone(good)
		g["/InstanceID"] = []string{"S:" + name}
		rules[name] = g
	}
	for field := range good {
		t.Run(field, func(t *testing.T) {
			changed := maps.Clone(rules["five"])
			changed[field] = []string{"S:foreign"}
			removed := 0
			err := executeNativeRuleCleanup(specs, func(s nativeRuleSpec) (firewallConstraints, error) {
				if s.Name == "five" {
					return changed, nil
				}
				return rules[s.Name], nil
			}, func() error { return nil }, func(nativeRuleSpec, string) error { removed++; return nil })
			if err == nil || removed != 0 {
				t.Fatalf("invalid final rule deleted earlier rules: %v %d", err, removed)
			}
		})
	}
	// An explicitly absent optional rule is skipped; the remaining four must
	// each retain the exact stable fingerprint at the deletion boundary.
	removed := 0
	reads := map[string]int{}
	err := executeNativeRuleCleanup(specs, func(s nativeRuleSpec) (firewallConstraints, error) {
		reads[s.Name]++
		if s.Name == "five" {
			return nil, nil
		}
		return rules[s.Name], nil
	}, func() error { return nil }, func(s nativeRuleSpec, hash string) error {
		want, _ := firewallFingerprint(rules[s.Name])
		if hash != want || reads[s.Name] != 5 {
			t.Fatal("delete before full preflight and double final read")
		}
		removed++
		return nil
	})
	if err != nil || removed != 4 {
		t.Fatalf("complete cleanup failed %v/%d", err, removed)
	}
}

func TestNativeRuleCleanupLateChangesAndOwnerFailuresDoNotDelete(t *testing.T) {
	spec, good := firewallPolicyFixture()
	for _, mode := range []string{"late_constraint", "projection", "enabled", "read_error", "missing", "owner_before", "owner_between", "owner_after", "owner_final"} {
		t.Run(mode, func(t *testing.T) {
			reads, owners, removed := 0, 0, 0
			err := executeNativeRuleCleanup([]nativeRuleSpec{spec}, func(nativeRuleSpec) (firewallConstraints, error) {
				reads++
				got := maps.Clone(good)
				if reads == 5 {
					switch mode {
					case "late_constraint":
						got["MSFT_NetAddressFilter/RemoteAddress"] = []string{"S:10.6.9.3"}
					case "projection":
						got["/Owner"] = []string{"NULL"}
					case "enabled":
						got["/Enabled"] = []string{"N:2"}
					case "read_error":
						return nil, errors.New("unreadable")
					case "missing":
						return nil, nil
					}
				}
				return got, nil
			}, func() error {
				owners++
				fail := map[string]int{"owner_before": 1, "owner_between": 3, "owner_after": 4, "owner_final": 8}[mode]
				if owners == fail {
					return errors.New("owner changed")
				}
				return nil
			}, func(nativeRuleSpec, string) error { removed++; return nil })
			if err == nil || removed != 0 {
				t.Fatalf("changed cleanup authorized: %v %d reads=%d owners=%d", err, removed, reads, owners)
			}
		})
	}
}

func TestNativeRuleCleanupExplicitAbsenceAndRequiredCallbacks(t *testing.T) {
	spec, good := firewallPolicyFixture()
	removed := 0
	remove := func(nativeRuleSpec, string) error { removed++; return nil }
	owner := func() error { return nil }
	read := func(nativeRuleSpec) (firewallConstraints, error) { return good, nil }
	if err := executeNativeRuleCleanup([]nativeRuleSpec{spec}, read, nil, remove); err == nil {
		t.Fatal("nil owner authorized cleanup")
	}
	if err := executeNativeRuleCleanup([]nativeRuleSpec{spec}, nil, owner, remove); err == nil {
		t.Fatal("nil reader authorized cleanup")
	}
	if err := executeNativeRuleCleanup([]nativeRuleSpec{spec}, read, owner, nil); err == nil {
		t.Fatal("nil remover accepted")
	}
	if err := executeNativeRuleCleanup([]nativeRuleSpec{spec, spec}, read, owner, remove); err == nil {
		t.Fatal("duplicate spec authorized cleanup")
	}
	if err := executeNativeRuleCleanup([]nativeRuleSpec{spec}, func(nativeRuleSpec) (firewallConstraints, error) { return nil, errors.New("read failed") }, owner, remove); err == nil {
		t.Fatal("unreadable inferred absent")
	}
	if err := executeNativeRuleCleanup([]nativeRuleSpec{spec}, func(nativeRuleSpec) (firewallConstraints, error) { return nil, nil }, func() error { return errors.New("owner unavailable") }, remove); err == nil {
		t.Fatal("absence bypassed owner")
	}
	if removed != 0 {
		t.Fatal("invalid authority reached mutation")
	}
}
