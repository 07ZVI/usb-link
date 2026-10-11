package ipadncm

import (
	"errors"
	"strings"
	"testing"
)

func TestPortableDisableUsesSDKDocumentedQuietPersistentFlags(t *testing.T) {
	// Microsoft cfgmgr32.h: 1=ABSOLUTE, 2=HARDWARE, 4=UI_NOT_OK, 8=PERSIST.
	// The old literal 3 silently requested HARDWARE and omitted persistence.
	if portableDisableFlags != 0x0c || portableDisableFlags&3 != 0 || portableDisableFlags&8 == 0 || portableDisableFlags&4 == 0 {
		t.Fatalf("incorrect Config Manager ABI flags: 0x%x", portableDisableFlags)
	}
}
func TestPortableProofRequiresAuthoritativeStateAndExactOriginalProperty(t *testing.T) {
	good := PortableNodeObservation{InstanceMatches: true, ClassMatches: true, RootMatches: true, StateReadable: true, FlagsReadable: true, Status: 0x01802400, Problem: 22, ConfigFlags: 0x81}
	if !good.targetReadBack(0x80, true) {
		t.Fatal("same disabled instance with owned preserved bits not accepted")
	}
	cases := []struct {
		name   string
		change func(*PortableNodeObservation)
	}{
		{"temporary CM disable without persistent flag", func(s *PortableNodeObservation) { s.ConfigFlags = 0x80 }},
		{"property changed but node still started", func(s *PortableNodeObservation) { s.Status |= 8 }},
		{"property changed but wrong problem", func(s *PortableNodeObservation) { s.Problem = 0 }},
		{"different instance", func(s *PortableNodeObservation) { s.InstanceMatches = false }},
		{"different USB root", func(s *PortableNodeObservation) { s.RootMatches = false }},
		{"different device class", func(s *PortableNodeObservation) { s.ClassMatches = false }},
		{"CM status read failed", func(s *PortableNodeObservation) { s.StateReadable = false }},
		{"native config property unavailable", func(s *PortableNodeObservation) { s.FlagsReadable = false }},
		{"needs reboot", func(s *PortableNodeObservation) { s.Status |= 0x100 }},
		{"other configuration bit changed", func(s *PortableNodeObservation) { s.ConfigFlags = 0x101 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := good
			tc.change(&s)
			if s.targetReadBack(0x80, true) {
				t.Fatal("unverified disable accepted", s)
			}
		})
	}
	restored := good
	restored.Problem = 0
	restored.Status |= 8
	restored.ConfigFlags = 0x80
	if !restored.targetReadBack(0x80, false) {
		t.Fatal("exact original flags and enabled CM state rejected")
	}
	restored.ConfigFlags = 0x81
	if restored.targetReadBack(0x80, false) {
		t.Fatal("restore accepted while owned disabled bit remains")
	}
}
func TestNetworkOnlyFailedApplicationCannotAdvertiseReadyOrReconnect(t *testing.T) {
	for _, initial := range []string{"READY", "ACTIVE"} {
		s := networkOnlyOperationState{status: initial, notice: "previous success"}
		s.fail(errors.New("portable readback unproven"))
		if !s.blocked || s.status != "ERROR" || s.notice != "portable readback unproven" {
			t.Fatal("failure advertised successful settings", s)
		}
		s.fail(nil)
		if !s.blocked || s.status != "ERROR" {
			t.Fatal("unverified retry cleared unresolved operation", s)
		}
	}
}
func TestPortableOperationHistoryIsBoundedImmutableAndRedactsSerial(t *testing.T) {
	var h portableOperationHistory
	for i := 0; i < 10; i++ {
		h.record(PortableNodeOperationDiagnostic{ElapsedMS: int64(i), NodePrefix: portableNodePrefix(`USB\VID_05AC&PID_12AB&REV_1316&MI_00\PRIVATE-SERIAL`)})
	}
	got := h.snapshot()
	if len(got) != 8 || got[0].ElapsedMS != 2 || got[7].ElapsedMS != 9 {
		t.Fatal("operation cache budget exceeded", got)
	}
	if strings.Contains(got[0].NodePrefix, "PRIVATE") {
		t.Fatal("full instance identity exposed")
	}
	got[0].Outcome = "mutated"
	if h.snapshot()[0].Outcome == "mutated" {
		t.Fatal("caller mutated cached operation")
	}
}

func TestPortableRecoveryCheckpointsOnlyStrictlyRestoredNodes(t *testing.T) {
	a := portableNodeReceipt{ID: "A"}
	b := portableNodeReceipt{ID: "B"}
	originalDisabled := portableNodeReceipt{ID: "originally-disabled", OriginalDisabled: true}
	durable := []portableNodeReceipt{a, originalDisabled, b}
	failSecond := errors.New("B native Enable failed")
	seen := []string{}
	err := restorePortableNodeReceipts(durable, func(n portableNodeReceipt) error {
		seen = append(seen, n.ID)
		if n.ID == "B" {
			return failSecond
		}
		return nil
	}, func(next []portableNodeReceipt) error {
		durable = append([]portableNodeReceipt(nil), next...)
		return nil
	})
	if err != failSecond || len(durable) != 2 || durable[0].ID != "originally-disabled" || durable[1].ID != "B" || strings.Join(seen, ",") != "A,B" {
		t.Fatal("failed node lost or unverified node changed", durable, seen, err)
	}
	// A can now be absent: recovery must not query a node already durably restored.
	err = restorePortableNodeReceipts(durable, func(n portableNodeReceipt) error {
		if n.ID != "B" {
			t.Fatal("queried removed/original-disabled node", n)
		}
		return nil
	}, func(next []portableNodeReceipt) error { durable = next; return nil })
	if err != nil || len(durable) != 1 || !durable[0].OriginalDisabled {
		t.Fatal("remaining exact restoration not checkpointed", durable, err)
	}
}
func TestPortableCheckpointFailureRetainsRecoveryObligation(t *testing.T) {
	durable := []portableNodeReceipt{{ID: "A"}, {ID: "B"}}
	writes := 0
	nativeCalls := 0
	diskError := errors.New("checkpoint not committed")
	err := restorePortableNodeReceipts(durable, func(portableNodeReceipt) error { nativeCalls++; return nil }, func([]portableNodeReceipt) error { writes++; return diskError })
	if err != diskError || writes != 1 || nativeCalls != 1 || len(durable) != 2 {
		t.Fatal("uncommitted recovery progressed", err, writes, nativeCalls, durable)
	}
	// Retry must perform A's readback again, even if the earlier enable returned
	// success; no in-memory acknowledgement can substitute for durable evidence.
	nativeCalls = 0
	err = restorePortableNodeReceipts(durable, func(portableNodeReceipt) error { nativeCalls++; return nil }, func(next []portableNodeReceipt) error { durable = next; return nil })
	if err != nil || nativeCalls != 2 || len(durable) != 0 {
		t.Fatal("recovery lost an uncommitted node", err, nativeCalls, durable)
	}
}
