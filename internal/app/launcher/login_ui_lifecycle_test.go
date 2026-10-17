package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestLoginUIRequiresExplicitAdmissionBeforeCreatingWindows(t *testing.T) {
	for _, test := range []struct {
		data      string
		want      bool
		confirmed bool
	}{
		{`{"admitted":true}`, true, true},
		{`{"admitted":false}`, false, true},
		{`{}`, false, false},
		{`{"admitted":null}`, false, false},
		{`{"admitted":"true"}`, false, false},
		{`{"admitted":true,"command":"anything"}`, false, false},
		{`{"admitted":true} {}`, false, false},
	} {
		if got, confirmed := loginUIAdmission([]byte(test.data)); got != test.want || confirmed != test.confirmed {
			t.Fatalf("admission %s: %v confirmed=%v", test.data, got, confirmed)
		}
	}
}

func TestLoginUIReadFailureOnlyStopsForVerifiedReplacement(t *testing.T) {
	for _, stage := range []string{"registration", "snapshot"} {
		for _, draining := range []bool{false, true} {
			for _, replacement := range []bool{false, true} {
				handoffs, stopped := 0, 0
				got := stopLoginUIForVerifiedReplacement(func() bool { return draining }, func() bool {
					handoffs++
					return replacement
				}, func() { stopped++ })
				want := draining || replacement
				if got != want || (stopped == 1) != want || stopped > 1 {
					t.Fatalf("%s drain=%v replacement=%v stopped=%d", stage, draining, replacement, stopped)
				}
				if draining && handoffs != 0 || !draining && handoffs != 1 {
					t.Fatalf("%s drain must not also launch replacement", stage)
				}
			}
		}
	}
}

func TestLoginUIBootstrapStillRequiresMigrationProofWhenUIDuplicate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time, 3)
	for range 3 {
		ticks <- time.Time{}
	}
	reads, confirmations := 0, 0
	complete := confirmLoginUIBootstrap(ctx, ticks, func() (bool, error) {
		reads++
		switch reads {
		case 1:
			return false, errors.New("unconfirmed")
		case 2:
			return true, nil
		default:
			return false, nil
		}
	}, func() { confirmations++ })
	if !complete || reads != 3 || confirmations != 1 {
		t.Fatalf("complete=%v reads=%d confirmations=%d", complete, reads, confirmations)
	}
	// Cancellation after a failed confirmation retains the failure cleanup.
	ticks = make(chan time.Time, 1)
	ticks <- time.Time{}
	if confirmLoginUIBootstrap(ctx, ticks, func() (bool, error) { return true, nil }, cancel) {
		t.Fatal("cancelled migration reported complete")
	}
}

func TestLoginUIReRegistrationRequiresExplicitDuplicateAfterCoreRecovery(t *testing.T) {
	// Repeated registration is independent of the first core's lifetime. A
	// failed read does not become a duplicate decision; the replacement core
	// must explicitly confirm whether this same UI owns its new registry slot.
	for _, sequence := range [][]string{
		{`{"admitted":true}`, ``, `{"admitted":true}`},
		{`{"admitted":true}`, ``, `{"admitted":false}`},
	} {
		closes := 0
		for _, reply := range sequence {
			admitted, confirmed := loginUIAdmission([]byte(reply))
			if confirmed && !admitted {
				closes++
			}
		}
		want := 0
		if sequence[2] == `{"admitted":false}` {
			want = 1
		}
		if closes != want {
			t.Fatalf("core recovery closes=%d want=%d", closes, want)
		}
	}
}

func TestLoginUIFollowsOnlyConfirmedRemoteReadyExit(t *testing.T) {
	for _, phase := range []string{"idle", "stopping", "restoring", "failed", "ready"} {
		for _, closeFollowers := range []bool{false, true} {
			for _, id := range []string{"", "stale", "0123456789abcdef0123456789abcdef"} {
				display, _ := json.Marshal(map[string]any{"desktop": map[string]any{"program_exit": map[string]any{
					"request_id": id, "phase": phase, "close_followers": closeFollowers,
				}}})
				want := phase == "ready" && closeFollowers && len(id) == 32
				if got := loginUIFollowExit(display); got != want {
					t.Fatalf("phase=%s close=%v id=%q: %v", phase, closeFollowers, id, got)
				}
			}
		}
	}
	for _, display := range []string{``, `{}`, `{"event":"backend-unavailable"}`, `{"desktop":{"program_exit":{"phase":"ready","close_followers":"true"}}}`} {
		if loginUIFollowExit(json.RawMessage(display)) {
			t.Fatalf("unconfirmed display triggered shutdown: %s", display)
		}
	}
}
