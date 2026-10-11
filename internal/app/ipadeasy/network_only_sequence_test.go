package ipadeasy

import (
	"reflect"
	"testing"
)

func TestNetworkOnlyPreparationOrdersProofIsolationAndDriver(t *testing.T) {
	for _, active := range []bool{false, true} {
		var calls []string
		err := PrepareWithNetworkOnly(active, func() string { calls = append(calls, "admit"); return "" }, func() string { calls = append(calls, "ensure"); return "" }, func() string { calls = append(calls, "driver"); return "" })
		want := []string{"driver", "ensure"}
		if active {
			want = []string{"admit", "ensure", "driver", "ensure"}
		}
		if err != "" || !reflect.DeepEqual(calls, want) {
			t.Fatal(active, err, calls)
		}
	}
}

func TestNetworkOnlyPreflightOrIsolationFailureCannotReachDriverModeOrStartup(t *testing.T) {
	for _, failAt := range []string{"proof", "pre-isolation", "driver", "post-isolation"} {
		var calls []string
		ensures := 0
		r := Run(func() string {
			return PrepareWithNetworkOnly(true, func() string {
				calls = append(calls, "proof")
				if failAt == "proof" {
					return "WRONG_ROOT_OR_OWNER"
				}
				return ""
			}, func() string {
				ensures++
				calls = append(calls, "ensure")
				if failAt == "pre-isolation" || failAt == "post-isolation" && ensures == 2 {
					return "ISOLATION_UNPROVEN"
				}
				return ""
			}, func() string {
				calls = append(calls, "driver")
				if failAt == "driver" {
					return "DRIVER_UNHEALTHY"
				}
				return ""
			})
		}, func() ModeOutcome { t.Fatal("failed preparation reached mode", failAt); return ModeOutcome{} }, func() { t.Fatal("failed preparation reached networking", failAt) })
		if r.Error == "" || r.ModeCheckRun || r.StartupCheckRun {
			t.Fatal(failAt, r, calls)
		}
		if failAt == "proof" && !reflect.DeepEqual(calls, []string{"proof"}) {
			t.Fatal("failed proof wrote nodes or prepared driver", calls)
		}
	}
}

func TestNetworkOnlyPostModeCannotMutateOnFailureAndRejectsChangedTarget(t *testing.T) {
	for _, outcome := range []ModeOutcome{{Error: "MODE_FAILED"}, {Ready: false}, {Ready: true, PauseAttempted: true, Restored: false}} {
		VerifyNetworkOnlyAfterMode(true, outcome, func() string { t.Fatal("failed mode performed isolation"); return "" })
	}
	VerifyNetworkOnlyAfterMode(false, ModeOutcome{Ready: true}, func() string { t.Fatal("non-I7 gained isolation step"); return "" })
	r := Run(func() string { return "" }, func() ModeOutcome {
		return VerifyNetworkOnlyAfterMode(true, ModeOutcome{Ready: true}, func() string { return "SAME_ROOT_PROOF_CHANGED" })
	}, func() { t.Fatal("changed target reached native start/networking") })
	if r.Error != "SAME_ROOT_PROOF_CHANGED" || r.StartupCheckRun {
		t.Fatal(r)
	}
}
