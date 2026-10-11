package macconnection

import (
	"encoding/json"
	"strings"
	"suhang/usbnet/internal/transport/bridge"
	"testing"
)

func TestProducerOwnershipJournalAccepted(t *testing.T) {
	r := bridge.NewOwnedSession("{A4611646-E050-4D25-B83E-633A5598F302}", "0123456789abcdef01234567")
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseSessionRecord(b)
	if err != nil || got != r {
		t.Fatalf("bridge journal rejected: %v %v", got, err)
	}
}

func TestOwnedJournalLegacyRecovery(t *testing.T) {
	for _, version := range []string{"0.4.1-phase02", "0.6.1-phase02", "0.6.2-phase02", bridge.SessionVersion, "0.8.15-independent-out"} {
		for _, status := range []string{"ACTIVE", "CLEAN", "CLEANUP_REQUIRED"} {
			r := bridge.NewOwnedSession("{A4611646-E050-4D25-B83E-633A5598F302}", "0123456789abcdef01234567")
			r.Version, r.Status = version, status
			b, _ := json.Marshal(r)
			if _, err := parseSessionRecord(b); err != nil {
				t.Fatalf("%s/%s: %v", version, status, err)
			}
		}
	}
}

func TestOwnedJournalRejectsUnverifiedRecovery(t *testing.T) {
	base := bridge.NewOwnedSession("{A4611646-E050-4D25-B83E-633A5598F302}", "0123456789abcdef01234567")
	cases := []bridge.OwnedSession{base, base, base, base, base}
	cases[0].Version = "0.8.16-independent-out"
	cases[1].Version = "0.8.15"
	cases[2].Status = "UNKNOWN"
	cases[3].GUID = "*"
	cases[4].Token = "*"
	for _, r := range cases {
		b, _ := json.Marshal(r)
		if _, err := parseSessionRecord(b); err == nil {
			t.Fatalf("accepted invalid record: %+v", r)
		}
	}
	for _, b := range [][]byte{[]byte("{bad}"), []byte("{}"), []byte(strings.Repeat(" ", 8193))} {
		if _, err := parseSessionRecord(b); err == nil {
			t.Fatal("accepted invalid JSON/oversize record")
		}
	}
}

func TestUpgradeReadinessRequiresMaintenanceListener(t *testing.T) {
	for _, c := range []struct {
		peer, listener bool
		err            string
		want           bool
	}{
		{true, true, "", true}, {true, false, "", false}, {false, true, "", false}, {true, true, "FILE_OWNED_ADAPTER_UNCONFIRMED", false},
	} {
		if got := RemoteReady(c.peer, c.listener, c.err); got != c.want {
			t.Fatalf("readiness %v: %v", c, got)
		}
	}
}

func TestRetainedProducerJournalRequiresExplicitPreparedAndFullMapping(t *testing.T) {
	v := bridge.NewOwnedSession("{A4611646-E050-4D25-B83E-633A5598F302}", "aaaaaaaaaaaaaaaaaaaaaaaa")
	v.Version = bridge.RetainedSessionVersion
	v.Retained = &bridge.RetainedAddress{Index: 7, LUID: 9, Created: 11, Mode: "persistent", ReceiptSHA256: strings.Repeat("b", 64), Prepared: true}
	b, _ := json.Marshal(v)
	if _, e := parseSessionRecord(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(string(b), `,"network_prepared":true`, "", 1), strings.Replace(string(b), `"created":11`, `"created":0`, 1), strings.Replace(string(b), `"created":11`, `"created":11,"CREATED":12`, 1), strings.Replace(string(b), bridge.RetainedSessionVersion, bridge.SessionVersion, 1)} {
		if _, e := parseSessionRecord([]byte(bad)); e == nil {
			t.Fatal("partial or downgraded retained ownership record accepted")
		}
	}
}

func TestResidentJournalRequiresExactNewRecoverySchema(t *testing.T) {
	v := bridge.NewOwnedSession("{A4611646-E050-4D25-B83E-633A5598F302}", "0123456789abcdef01234567")
	v.Version = bridge.ResidentSessionVersion
	for _, status := range []string{"ACTIVE", "CLEAN", "CLEANUP_REQUIRED"} {
		v.Status = status
		b, _ := json.Marshal(v)
		got, e := parseSessionRecord(b)
		if e != nil || got != v {
			t.Fatalf("resident %s rejected: %v", status, e)
		}
		for _, changed := range []string{
			strings.Replace(string(b), `"status":`, `"status":"ACTIVE","status":`, 1),
			strings.Replace(string(b), `"guid":`, `"guid":"{00000000-0000-0000-0000-000000000000}","guid":`, 1),
			strings.TrimSuffix(string(b), "}") + `,"retained_address":null}`,
		} {
			if _, e := parseSessionRecord([]byte(changed)); e == nil {
				t.Fatal("resident duplicate/retained schema admitted")
			}
		}
	}
}
