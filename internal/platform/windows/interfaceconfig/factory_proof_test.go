package interfaceconfig

import (
	"errors"
	"strings"
	"testing"
)

func TestFactoryCheckpointFreshProofFailureHasNoCommit(t *testing.T) {
	s := Scope{"host", HostGUID, 7, 9}
	sha := strings.Repeat("a", 64)
	a := ActiveOwnership{s, 11, sha, "persistent"}
	for fail := 0; fail <= 8; fail++ {
		n, commits := 0, 0
		step := func() error {
			n++
			if n == fail {
				return errors.New("fault")
			}
			return nil
		}
		e := runFactoryProofCheckpoint(s, sha, "persistent", 0, step, func() (ActiveOwnership, error) { return a, step() }, step, func(v ActiveOwnership) error { commits++; return step() })
		if fail == 0 && (e != nil || commits != 1) {
			t.Fatal("no-op fault path", e, commits)
		}
		if fail > 0 && e == nil {
			t.Fatal("fault ignored", fail)
		}
		if fail >= 1 && fail <= 5 && commits != 0 {
			t.Fatal("checkpoint before complete fresh proof", fail)
		}
		if fail >= 6 && commits != 1 {
			t.Fatal("post-check fault must retain committed unknown obligation", fail, commits)
		}
	}
	for _, changed := range []ActiveOwnership{{Scope{"host", HostGUID, 8, 9}, 11, sha, "persistent"}, {s, 12, sha, "persistent"}, {s, 11, strings.Repeat("b", 64), "persistent"}, {s, 11, sha, "legacy"}} {
		n, c := 0, 0
		e := runFactoryProofCheckpoint(s, sha, "persistent", 0, func() error { return nil }, func() (ActiveOwnership, error) {
			n++
			if n == 1 {
				return a, nil
			}
			return changed, nil
		}, func() error { return nil }, func(ActiveOwnership) error { c++; return nil })
		if e == nil || c != 0 {
			t.Fatal("changed complete proof reached checkpoint", changed)
		}
	}
}

func TestHostRestoreCheckpointCannotConsumePendingOriginals(t *testing.T) {
	r := configReceipt{Version: 1, RestoreRequested: true}
	if hostOriginalsRestored(r) != nil {
		t.Fatal("completed durable host restore rejected")
	}
	r.DAD = []dadOriginal{{Scope: Scope{"mac", MacGUID, 8, 10}, Original: 1}}
	if hostOriginalsRestored(r) != nil {
		t.Fatal("other role obligations are not consumed by host checkpoint")
	}
	r.DAD = append(r.DAD, dadOriginal{Scope: Scope{"host", HostGUID, 7, 9}, Original: 1})
	if hostOriginalsRestored(r) == nil {
		t.Fatal("pending host DAD checkpointed")
	}
	r.DAD = nil
	r.Persistent = []persistentOriginal{{Scope: Scope{"host", HostGUID, 7, 9}}}
	if hostOriginalsRestored(r) == nil {
		t.Fatal("pending host Store checkpointed")
	}
	r.Persistent = nil
	r.RestoreRequested = false
	if hostOriginalsRestored(r) == nil {
		t.Fatal("normal service close must not consume uninstall checkpoint")
	}
}
