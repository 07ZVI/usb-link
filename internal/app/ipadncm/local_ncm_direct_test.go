//go:build usblink_local_remote

package ipadncm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLocalNCMDirectPacketDoesNotExpandNormalAllowlist(t *testing.T) {
	if _, e := appleModePacket(0xc0, 0x52, 0, 5, 1); e == nil {
		t.Fatal("normal mode admitted experiment")
	}
	if !bytes.Equal(localDirectMode5Packet(), []byte{0xc0, 0x52, 0, 0, 5, 0, 1, 0, 0}) {
		t.Fatal("wrong fixed experimental packet")
	}
}

func TestLocalNCMDirectDescriptorEvidenceIsNotNetworkAdmission(t *testing.T) {
	c := Configuration{Value: 1, NCMControls: 1, Interfaces: []Interface{{Class: 2, Subclass: 13}, {Class: 10}, {Class: 10, Alternate: 1}}}
	if !directOnlyNCMLayout([]Configuration{c}, 1) {
		t.Fatal("direct descriptor shape missed")
	}
	for _, config := range []Configuration{{Value: 5, NCMControls: 1, Interfaces: c.Interfaces}, {Value: 1, NCMControls: 2, Interfaces: c.Interfaces}, {Value: 1, NCMControls: 1, Interfaces: append(append([]Interface(nil), c.Interfaces...), Interface{Class: 6})}} {
		if directOnlyNCMLayout([]Configuration{config}, 1) {
			t.Fatal("ambiguous/PTP layout admitted")
		}
	}
	if directOnlyNCMLayout([]Configuration{c, c}, 1) || directOnlyNCMLayout([]Configuration{c}, 5) {
		t.Fatal("configuration selector confused with mode")
	}
}

func TestLocalNCMDirectRecoveryRecordStrict(t *testing.T) {
	j := localNCMDirectJournal{Schema: 1, Root: `USB\VID_05AC&PID_12AB\0123456789ABCDEF`, Hub: `\\?\usb#hub`, Port: 1, SerialSHA256: strings.Repeat("a", 64), OriginalConfiguration: 3, OriginalConfigurationSHA256: strings.Repeat("b", 64), OriginalProbe: []byte{3, 3, 3, 0}, RequestedMode: 5}
	b, _ := json.Marshal(j)
	if _, e := decodeLocalNCMDirectJournal(b); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*localNCMDirectJournal){func(j *localNCMDirectJournal) { j.RequestedMode = 1 }, func(j *localNCMDirectJournal) { j.Root = `USB\VID_05AC&PID_12A8\OTHER` }, func(j *localNCMDirectJournal) { j.OriginalConfiguration = 5 }, func(j *localNCMDirectJournal) { j.OriginalProbe = nil }, func(j *localNCMDirectJournal) { j.SerialSHA256 = "" }} {
		bad := j
		mutate(&bad)
		v, _ := json.Marshal(bad)
		if _, e := decodeLocalNCMDirectJournal(v); e == nil {
			t.Fatal("unsafe recovery intent accepted")
		}
	}
	for _, bad := range [][]byte{append(append([]byte(nil), b...), []byte("{}")...), []byte(strings.Replace(string(b), `"schema":1`, `"schema":1,"unknown":true`, 1)), bytes.Repeat([]byte(" "), 8193)} {
		if _, e := decodeLocalNCMDirectJournal(bad); e == nil {
			t.Fatal("invalid record accepted")
		}
	}
}

func waitDirectState(t *testing.T, c *localNCMDirectController, condition func(localNCMDirectStatus) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition(c.snapshot()) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state did not settle: %+v", c.snapshot())
}

func TestLocalNCMDirectVerifiedRecoveryResolvesOnlyPreviousRun(t *testing.T) {
	for _, phase := range []string{"replug_required", "direct_network_incomplete", "direct_network_stopping", "experiment_incomplete"} {
		t.Run(phase, func(t *testing.T) {
			c := newLocalNCMDirectController()
			c.state.RecoveryRequired = true
			c.state.Phase, c.state.Error = phase, "DIRECT_PEER_VERIFICATION_FAILED_TIMEOUT"
			c.recoveryStatus(nil)
			s := c.snapshot()
			if s.RecoveryRequired || s.Error != "" || s.Phase != "recovery_verified" {
				t.Fatalf("verified previous run retained failure: %+v", s)
			}
		})
	}
	for _, scenario := range []string{"no_obligation", "running", "session_pending_cleanup", "preference_save_failed", "preference_read_failed", "unrelated_phase", "recovery_failed"} {
		t.Run(scenario, func(t *testing.T) {
			c := newLocalNCMDirectController()
			c.state.RecoveryRequired = true
			c.state.Phase, c.state.Error = "direct_network_incomplete", "DIRECT_NETWORK_CANCELLED"
			var recoveryError error
			switch scenario {
			case "no_obligation":
				c.state.RecoveryRequired = false
			case "running":
				c.running = true
			case "session_pending_cleanup":
				c.sessionCancel = func() {}
			case "preference_save_failed":
				c.state.Persistence = "failed"
				c.state.Error = "DIRECT_PREFERENCE_FAILED"
			case "preference_read_failed":
				c.state.Error = "DIRECT_PREFERENCE_UNAVAILABLE"
			case "unrelated_phase":
				c.state.Phase = "selected_for_next_connection"
			case "recovery_failed":
				recoveryError = errors.New("DIRECT_REPLUG_REQUIRED")
			}
			before := c.snapshot()
			c.recoveryStatus(recoveryError)
			s := c.snapshot()
			if recoveryError != nil {
				if !s.RecoveryRequired || s.Phase != "replug_required" || s.Error != recoveryError.Error() {
					t.Fatalf("recovery failure hidden: %+v", s)
				}
			} else if s.Error != before.Error || s.Phase != before.Phase {
				t.Fatalf("unrelated or active state erased: before=%+v after=%+v", before, s)
			}
		})
	}
}

func TestLocalNCMDirectMasterOffRevokesPendingRestore(t *testing.T) {
	c := newLocalNCMDirectController()
	c.ctx = context.Background()
	entered, release := make(chan struct{}), make(chan struct{})
	c.configure(nil, func() (bool, error) { close(entered); <-release; return true, nil })
	c.masterChanged(true)
	<-entered
	c.masterChanged(false)
	close(release)
	waitDirectState(t, c, func(s localNCMDirectStatus) bool { return s.Persistence == "saved" })
	s := c.snapshot()
	if s.Requested || !s.SavedEnabled || c.allowed(c.revision) {
		t.Fatal("late disk read restored runtime permission")
	}
}

func TestLocalNCMDirectPersistenceFailureNeverArms(t *testing.T) {
	c := newLocalNCMDirectController()
	c.ctx = context.Background()
	c.master = true
	c.configure(func(bool) error { return errors.New("disk") }, nil)
	if e := c.set(true, strings.Repeat("1", 32)); e != nil {
		t.Fatal(e)
	}
	waitDirectState(t, c, func(s localNCMDirectStatus) bool { return s.Persistence == "failed" })
	if c.allowed(c.revision) || c.snapshot().Effective {
		t.Fatal("failed persistence armed mode")
	}
	c.masterChanged(false)
	if e := c.set(true, strings.Repeat("2", 32)); e == nil || c.snapshot().RejectedID != strings.Repeat("2", 32) {
		t.Fatal("master gate lost request acknowledgement")
	}
}

func TestLocalNCMDirectSnapshotCopiesDescriptorSlices(t *testing.T) {
	c := newLocalNCMDirectController()
	c.state.Configurations = []Configuration{{Value: 1, Interfaces: []Interface{{Class: 2}}}}
	c.state.OriginalProbe = []byte{3, 3, 3, 0}
	s := c.snapshot()
	s.Configurations[0].Interfaces[0].Class = 99
	s.OriginalProbe[0] = 9
	if c.snapshot().Configurations[0].Interfaces[0].Class != 2 || c.snapshot().OriginalProbe[0] != 3 {
		t.Fatal("snapshot aliases live state")
	}
}

func TestLocalNCMDirectBoundedDescriptorPayload(t *testing.T) {
	v, b := uint16(65535), byte(255)
	s := newLocalNCMDirectController().snapshot()
	s.Error = "DIRECT_NCM_OBSERVED_NETWORK_UNSUPPORTED_REPLUG_REQUIRED"
	s.RequestID = strings.Repeat("f", 32)
	s.RejectedID = s.RequestID
	s.RejectedError = "DIRECT_LOCAL_DIAGNOSTICS_REQUIRED"
	s.Phase = "direct_failed_fallback_mode3_verified"
	c := Configuration{Index: 255, Value: 255, NCMControls: 8, Associations: make([]Association, 2)}
	for i := 0; i < 4; i++ {
		n := Interface{Number: 255, Alternate: 255, Class: 255, Subclass: 255, Protocol: 255, Slaves: []byte{255, 255}}
		for k := 0; k < 3; k++ {
			n.Endpoints = append(n.Endpoints, Endpoint{Address: 255, Type: 255, MaxPacket: 65535})
		}
		for k := 0; k < 4; k++ {
			n.Functions = append(n.Functions, FunctionalDescriptor{Subtype: 255, Length: 255, Version: &v, Capabilities: &b, MaxSegment: &v})
		}
		c.Interfaces = append(c.Interfaces, n)
	}
	s.Configurations = []Configuration{c}
	s.Nodes = make([]trustNodeState, 4)
	s.Binding = &directBindingEvidence{Source: "cached_pnp_registry", IDShape: "mi00_variant", Service: "unavailable", INF: strings.Repeat("a", 60) + ".inf", LowerCount: 4096, UpperCount: 4096, LowerKinds: [2]string{"AppleLowerFilter", "AppleLowerFilter"}, UpperKinds: [2]string{"AppleLowerFilter", "AppleLowerFilter"}, Failure: "DIRECT_NCM_SERVICE_BINDING_UNPROVEN", NativeResult: "DIRECT_NCM_DRIVER_REGISTRY_UNAVAILABLE", NativeINF: strings.Repeat("b", 60) + ".inf", NativeProvider: "unavailable"}
	s.Binding.DescriptorBCD = "FFFF"
	s.Binding.IDTokens = directIDTokens(`USB\VID_05AC&PID_12AB&REV_FFFF&CDC_0D&MI_00&MI_00`)
	s.Network = &directNetworkEvidence{NICCount: 4096, PeerStage: "verifying", PeerStatus: strings.Repeat("X", 96), NeighborCount: 4096, EchoCount: 4096, ParsedEchoes: 4096, NonceMatches: 4096, ScopedRoundtrips: 4096}
	payload, e := json.Marshal(s)
	if e != nil || len(payload) > 6000 {
		t.Fatalf("descriptor budget: %d %v", len(payload), e)
	}
}
