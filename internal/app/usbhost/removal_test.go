package usbhost

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRemovalInterruptedObligation(t *testing.T) {
	b, _ := json.Marshal(priorJournal())
	original := removalIntent{Version: 1, JournalSHA256: journalDigest(b), Instance: `ROOT\NET\0001`, Ticks: 1000, State: "intent"}
	for _, state := range []string{"intent", "restart_required", "flags_unreadable"} {
		p := original
		p.State = state
		for _, ticks := range []uint64{0, 1000, 1001, 900000} {
			if removalRecoveryGate(p, b, true, ticks) == nil {
				t.Fatalf("%s accepted unknown reset %d", state, ticks)
			}
		}
		if removalRecoveryGate(p, b, true, 999) != nil {
			t.Fatalf("%s rejected strict counter reset", state)
		}
		if removalRecoveryGate(p, nil, false, 1) == nil {
			t.Fatal("missing original journal discarded")
		}
	}
	changed := priorJournal()
	changed.Created++
	foreign, _ := json.Marshal(changed)
	if removalRecoveryGate(original, foreign, true, 1) == nil {
		t.Fatal("foreign journal accepted")
	}
	complete := original
	complete.State = "complete"
	if removalRecoveryGate(complete, b, true, 999999) != nil || removalRecoveryGate(complete, nil, false, 999999) != nil {
		t.Fatal("verified complete checkpoint cannot resume cleanup")
	}
	if removalRecoveryGate(complete, foreign, true, 1) == nil {
		t.Fatal("complete checkpoint adopted changed journal")
	}
}

func TestRemovalIntentStrictShape(t *testing.T) {
	b, _ := json.Marshal(priorJournal())
	p := removalIntent{Version: 1, JournalSHA256: journalDigest(b), Instance: `ROOT\NET\0001`, Ticks: 1, State: "intent"}
	raw, _ := json.Marshal(p)
	got, e := decodeRemovalIntent(raw)
	if e != nil || got != p {
		t.Fatal("valid intent", e)
	}
	changes := []func(*removalIntent){func(x *removalIntent) { x.Version = 2 }, func(x *removalIntent) { x.Ticks = 0 }, func(x *removalIntent) { x.Instance = "" }, func(x *removalIntent) { x.Instance = "ROOT*" }, func(x *removalIntent) { x.JournalSHA256 = strings.Repeat("z", 64) }, func(x *removalIntent) { x.State = "absent_means_complete" }}
	for _, change := range changes {
		x := p
		change(&x)
		v, _ := json.Marshal(x)
		if _, e := decodeRemovalIntent(v); e == nil {
			t.Fatal("malformed intent accepted", string(v))
		}
	}
	for _, v := range []string{string(raw) + ` {}`, strings.TrimSuffix(string(raw), "}") + `,"unknown":1}`, strings.TrimSuffix(string(raw), "}") + `,"state":"complete"}`} {
		if _, e := decodeRemovalIntent([]byte(v)); e == nil {
			t.Fatal("unknown/trailing input accepted")
		}
	}
}

// Source contracts supplement native compile fixtures; these do not claim
// SetupAPI, ACLs or DIF_REMOVE were executed on this macOS test host.
func TestRemovalNativeProductionBoundary(t *testing.T) {
	b, e := os.ReadFile("host_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	start := strings.Index(s, "func Recover(")
	end := strings.Index(s[start:], "\nfunc Start(")
	r := s[start : start+end]
	for _, forbidden := range []string{"netconfig.Run(", "RecoverAdapter(", "RunReadOnlySharedHostIdentity("} {
		if strings.Contains(r, forbidden) {
			t.Fatal("runtime recovery retains script path", forbidden)
		}
	}
	if strings.Index(r, "readRemovalIntentFile(dir)") > strings.Index(r, "if !present {") {
		t.Fatal("absence bypasses interrupted deletion obligation")
	}
	for _, required := range []string{"VerifySharedHostRecoveryIdentityNative(index)", "return errOwnedNonpresentRecreate", "remove(p)", "removeNative(ctx", "RemoveVerifiedSharedHostNative", "journalDigest(b)", "writeRemovalIntentFile(dir,pending,false)"} {
		if !strings.Contains(strings.ReplaceAll(r, " ", ""), strings.ReplaceAll(required, " ", "")) {
			t.Fatal("missing durable native removal boundary", required)
		}
	}
	if strings.Contains(r, "RemoveVerifiedNonpresentSharedHostNative") {
		t.Fatal("cold nonpresent recovery still actively removes the device")
	}
	b, e = os.ReadFile("removal_store_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s = string(b)
	for _, required := range []string{"SecurityDescriptor: sd", "windows.CREATE_NEW", "windows.GetSecurityInfo(h", "windows.FILE_FLAG_OPEN_REPARSE_POINT", "f.Sync()", "windows.MOVEFILE_WRITE_THROUGH", "ConfirmSharedHostRemovalAbsentNative(v.Instance)"} {
		if !strings.Contains(s, required) {
			t.Fatal("missing protected/native checkpoint", required)
		}
	}
	if strings.Contains(s, "SetSecurityInfo(") || strings.Contains(s, "Now().") {
		t.Fatal("post-creation ACL/estimated boot time introduced")
	}
}
