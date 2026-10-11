package ipadncm

import (
	"errors"
	"reflect"
	"testing"
)

func TestTrustRevokeExactSerialLeaves(t *testing.T) {
	cases := []struct {
		serial string
		want   []string
	}{
		{"000081030009716E3400201E", []string{"000081030009716e3400201e.plist", "00008103-0009716e3400201e.plist"}},
		{"00008103-0009716E3400201E", []string{"000081030009716e3400201e.plist", "00008103-0009716e3400201e.plist"}},
		{"0123456789abcdef0123456789abcdef01234567", []string{"0123456789abcdef0123456789abcdef01234567.plist"}},
	}
	for _, c := range cases {
		if got := trustRevokeLeaves(c.serial); !reflect.DeepEqual(got, c.want) {
			t.Errorf("serial %q: got %v", c.serial, got)
		}
	}
	for _, s := range []string{"", "*", "../000081030009716E3400201E", "000081030009716E3400201E.plist", "00008103_0009716E3400201E", "00008103-0009716E3400201G", "00008103-0009716E3400201E ", "00008103-0009716E3400201E:stream"} {
		if len(trustRevokeLeaves(s)) != 0 {
			t.Errorf("unsafe serial accepted: %q", s)
		}
	}
	if !trustRevokeOldManualTarget(cases[0].serial) || !trustRevokeOldManualTarget(cases[1].serial) || trustRevokeOldManualTarget("000081030009716E3400201F") || trustRevokeOldManualTarget(cases[2].serial) {
		t.Fatal("manual backup deletion widened beyond the documented device")
	}
}

func TestTrustRevokeInterruptedMoveRetainsRecoveryBoundary(t *testing.T) {
	names := []string{"durable_intent", "fresh_identity", "handle_move", "protect_owner_and_acl", "durable_final_move", "independent_readback", "durable_completion"}
	sentinel := errors.New("injected interruption")
	for failed := 0; failed < len(names); failed++ {
		t.Run(names[failed], func(t *testing.T) {
			var called []int
			steps := make([]func() error, len(names))
			for i := range steps {
				steps[i] = func() error {
					called = append(called, i)
					if i == failed {
						return sentinel
					}
					return nil
				}
			}
			err := runTrustRevokeTransaction(steps[0], steps[1], steps[2], steps[3], steps[4], steps[5], steps[6])
			if !errors.Is(err, sentinel) || len(called) != failed+1 {
				t.Fatalf("failure advanced effects: %v %v", err, called)
			}
			for i, step := range called {
				if step != i {
					t.Fatal("effects reordered")
				}
			}
		})
	}
	calls := 0
	ok := func() error { calls++; return nil }
	if err := runTrustRevokeTransaction(ok, ok, ok, ok, ok, ok, ok); err != nil || calls != 7 {
		t.Fatalf("completion: %d %v", calls, err)
	}
}

func TestTrustRevokeRejectsLinksDirectoriesAndOversizedFiles(t *testing.T) {
	if err := trustRevokeFileShape(0x20, 1, 4096); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		attrs, links uint32
		size         uint64
	}{{0x10, 1, 4096}, {0x400, 1, 4096}, {0x410, 1, 4096}, {0x20, 0, 4096}, {0x20, 2, 4096}, {0x20, 1, 0}, {0x20, 1, 512*1024 + 1}} {
		if err := trustRevokeFileShape(c.attrs, c.links, c.size); err == nil {
			t.Errorf("unsafe file accepted: %+v", c)
		}
	}
}
