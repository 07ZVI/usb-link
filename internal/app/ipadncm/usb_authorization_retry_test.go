package ipadncm

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPreflightFailureClassification(t *testing.T) {
	ok := preflightFacts{DeviceCount: 1, RootUnique: true, DescriptorRead: true, Configuration: 3}
	cases := []struct {
		name string
		f    preflightFacts
		want bool
	}{
		{"enumeration time limit", preflightFacts{SnapshotError: "TIME_LIMIT"}, true},
		{"no device yet", preflightFacts{DeviceCount: 0}, true},
		{"two devices", preflightFacts{DeviceCount: 2}, true},
		{"descriptor timeout WIN32_31", preflightFacts{DeviceCount: 1, RootUnique: true, DeviceErrors: []string{"CONFIG_0_READ_WIN32_31"}}, true},
		{"descriptor 1460", preflightFacts{DeviceCount: 1, RootUnique: true, DeviceErrors: []string{"CONFIG_1_READ_WIN32_1460", "CONFIG_2_HEADER_UNAVAILABLE"}}, true},
		{"string read failed", preflightFacts{DeviceCount: 1, RootUnique: true, DeviceErrors: []string{"USB_SERIAL_OR_PRODUCT_DESCRIPTOR_UNCONFIRMED"}, SerialStatus: "USB_STRING_READ_WIN32_31", ProductStatus: "USB_STRING_VERIFIED"}, true},
		{"root not yet unique", preflightFacts{DeviceCount: 1, DescriptorRead: true, Configuration: 3}, true},
		{"configuration 0", preflightFacts{DeviceCount: 1, RootUnique: true, DescriptorRead: true, Configuration: 0}, true},
		{"serial mismatch", preflightFacts{DeviceCount: 1, RootUnique: true, DeviceErrors: []string{"USB_DESCRIPTOR_NATIVE_SERIAL_MISMATCH_OR_ROOT_ABSENT"}}, false},
		{"root not unique error", preflightFacts{DeviceCount: 1, RootUnique: true, DeviceErrors: []string{"USB_DESCRIPTOR_ROOT_NOT_UNIQUE"}}, false},
		{"hub binding", preflightFacts{DeviceCount: 1, RootUnique: true, DeviceErrors: []string{"USB_DESCRIPTOR_EXACT_NATIVE_HUB_BINDING_FAILED"}}, false},
		{"mixed with identity conflict", preflightFacts{DeviceCount: 1, RootUnique: true, DeviceErrors: []string{"CONFIG_0_READ_WIN32_31", "USB_DESCRIPTOR_ROOT_NOT_UNIQUE"}}, false},
		{"malformed serial", preflightFacts{DeviceCount: 1, RootUnique: true, DeviceErrors: []string{"USB_SERIAL_OR_PRODUCT_DESCRIPTOR_UNCONFIRMED"}, SerialStatus: "USB_STRING_VALUE_INVALID", ProductStatus: "USB_STRING_READ_WIN32_31"}, false},
		{"malformed config", preflightFacts{DeviceCount: 1, RootUnique: true, DeviceErrors: []string{"CONFIG_SIZE_INVALID"}}, false},
		{"settled unsupported layout", ok, false},
		{"settled unsupported configuration", preflightFacts{DeviceCount: 1, RootUnique: true, DescriptorRead: true, Configuration: 4}, false},
	}
	for _, c := range cases {
		if got := preflightFailureTransient(c.f); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestInitialConfigurationClassification(t *testing.T) {
	for state, want := range map[string]bool{
		"INITIAL_CONFIGURATION_TIMEOUT": true, "INITIAL_CONFIGURATION_TARGET_CHANGED_OR_UNREADABLE": true,
		"INITIAL_CONFIGURATION_CANCELLED": false, "INITIAL_CONFIGURATION_UNSUPPORTED": false,
	} {
		if initialConfigurationTransient(state, preflightFacts{}) != want {
			t.Error(state)
		}
	}
	read := preflightFacts{DeviceCount: 1, RootUnique: true, DeviceErrors: []string{"CONFIG_0_READ_WIN32_31"}}
	if !initialConfigurationTransient("INITIAL_CONFIGURATION_FULL_PROOF_FAILED", read) {
		t.Fatal("unreadable full proof should retry")
	}
	changed := preflightFacts{DeviceCount: 1, RootUnique: true, DescriptorRead: true, Configuration: 3}
	if initialConfigurationTransient("INITIAL_CONFIGURATION_FULL_PROOF_FAILED", changed) {
		t.Fatal("a readable but different target must keep the pause")
	}
}

func TestAuthorizationFailureCodeAndRetryDecision(t *testing.T) {
	const legacy = "USB_LAYOUT_UNCONFIRMED_DECLINED_OR_CHANGED"
	transient := authorizationOutcome{Status: "USB_PREFLIGHT_UNCONFIRMED", Transient: true}
	got := authorizationFailureError(transient, legacy)
	if !isAuthorizationTransientError(got) || !strings.Contains(got, "USB_PREFLIGHT_UNCONFIRMED") {
		t.Fatal(got)
	}
	var b autoRetryBudget
	if b.delay(got, false) != 5*time.Second {
		t.Fatal("readiness failure must auto-retry")
	}
	for _, o := range []authorizationOutcome{
		{Status: "USB_DECLINED_CANCELLED_OR_CHANGED"},
		{Status: "USB_DECLINED_CANCELLED_OR_CHANGED", Transient: true, Interactive: true},
		{Status: "USB_PREFLIGHT_UNCONFIRMED", Transient: true, Interactive: true},
		{Status: "USB_UNEXPECTED_HID_INTERFACE"},
		{Transient: true},
	} {
		if e := authorizationFailureError(o, legacy); e != legacy || b.delay(e, false) != 0 {
			t.Fatal("must keep pausing", o, e)
		}
	}
	if e := modeFailureError("MODE_CHANGE_DECLINED", transient); !isAuthorizationTransientError(e) {
		t.Fatal(e)
	}
	if e := modeFailureError("MODE_CHANGE_DECLINED", authorizationOutcome{Status: "USB_DECLINED_CANCELLED_OR_CHANGED"}); e != "MODE_CHANGE_DECLINED" || b.delay(e, false) != 0 {
		t.Fatal(e)
	}
	if e := modeFailureError("NCM_NOT_ACTIVE_AFTER_MODE_CHECK", transient); e != "NCM_NOT_ACTIVE_AFTER_MODE_CHECK" {
		t.Fatal(e)
	}
}

func TestPreModeReadinessStatusesRetryButDecisionsDoNot(t *testing.T) {
	for _, s := range []string{"INVENTORY_INCOMPLETE", "NEED_ONE_APPLE_MOBILE_DEVICE", "NETWORK_ONLY_USB_LAYOUT_NOT_READY", "USB_TARGET_CHANGED_NO_CONTROL_REQUEST", "CONTROL_ACCESS_BLOCKED_NOT_A_SUPPORT_VERDICT", "APPLICATION_HOST_FLAGS_UNAVAILABLE: WIN32_1168"} {
		var b autoRetryBudget
		if b.delay(s, false) == 0 {
			t.Error("not retried", s)
		}
	}
	for _, s := range []string{"NETWORK_ONLY_USB_LAYOUT_UNCONFIRMED", "MODE_CHANGE_DECLINED", "MODE_CHANGE_DECLINED_OR_CANCELLED", "MODE_NOT_INITIAL_NO_CHANGE", "MODE_REQUEST_SENT_NCM_NOT_OBSERVED", "PHOTO_ISOLATION_RECOVERY_OR_SCOPE_UNCONFIRMED", "USB_SECURITY_INVENTORY_UNAVAILABLE", "USB_UNEXPECTED_HID_INTERFACE"} {
		var b autoRetryBudget
		if b.delay(s, false) != 0 {
			t.Error("must keep pausing", s)
		}
	}
	b := autoRetryBudget{used: 3}
	if b.delay(authorizationTransientError("USB_PREFLIGHT_UNCONFIRMED"), false) != 0 {
		t.Fatal("unbounded")
	}
}

func TestAttemptFailureLogFlagsFirstFailureOfAttachment(t *testing.T) {
	l := newAttemptFailureLog()
	now := time.Unix(100, 0)
	for i := 0; i < 6; i++ {
		l.record(attemptFailureRecord{SoftwareAttempt: uint64(i), Code: "X", ReadErrorCodes: []string{"a", "b", "c", "d", "e"}}, now)
	}
	got := l.snapshot()
	if len(got) != 4 || !got[0].FirstOfAttachment || got[1].FirstOfAttachment || len(got[0].ReadErrorCodes) != 4 {
		t.Fatal(got)
	}
	l.newAttachment()
	l.record(attemptFailureRecord{SoftwareAttempt: 9, Code: "Y"}, now)
	got = l.snapshot()
	if !got[len(got)-1].FirstOfAttachment {
		t.Fatal(got)
	}
}

func TestTrustPromptDiagnosticCarriesRequiredFields(t *testing.T) {
	c := onKnown(newKnownFake())
	c.step()
	c.applyKnown()
	p := c.snapshot()
	d := trustPromptDiagnosticFrom(p, authorizationOutcome{Status: "USB_PREFLIGHT_UNCONFIRMED", Transient: true}, nil)
	b, _ := json.Marshal(d)
	for _, k := range []string{"known_photo_instances", "applied_before_mode_request", "before_mode_request_ran", "recent_attempt_failures", "photo_first_sightings", "consent_status"} {
		if !strings.Contains(string(b), k) {
			t.Fatal(k, string(b))
		}
	}
	if !p.PreModeRan || p.PreModeApplied || p.PreModeKnown != 0 {
		t.Fatal("first-ever connection has nothing to apply", p)
	}
}

func TestPreModePassReportsAppliedAndFirstSighting(t *testing.T) {
	f := newKnownFake()
	c := onKnown(f)
	c.step()
	cfg5 := knownCfg("CFG5")
	f.add(cfg5, knownDev{registered: true})
	f.remember(cfg5)
	c.known = f.known
	c.mu.Lock()
	c.root = cfg5.Root
	c.mu.Unlock()
	c.applyKnown()
	p := c.snapshot()
	if !p.PreModeRan || !p.PreModeApplied || p.PreModeKnown != 1 {
		t.Fatal(p)
	}
	other := knownCfg("CFG3")
	f.add(other, knownDev{registered: true, present: true})
	f.nodes = []portableNodeReceipt{other}
	c.step()
	s := c.snapshot()
	if len(s.Sightings) != 1 || s.Sightings[0].KnownMatch || s.Sightings[0].DisabledAtFirstSight || s.KnownLearned != 1 {
		t.Fatal(s)
	}
}
