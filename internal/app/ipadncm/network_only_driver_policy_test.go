package ipadncm

import (
	"strings"
	"testing"
)

func TestExpectedNetworkOnlyStopRequiresOwnedFreshScopeAndNativePolicy(t *testing.T) {
	valid := networkOnlyDriverProof{true, true, true, true, true, true, true, true, true, 1, 3, 3}
	if !valid.admitsExpectedStop() {
		t.Fatal("owned manual/stopped isolation rejected")
	}
	for name, breakProof := range map[string]func(*networkOnlyDriverProof){
		"ordinary stopped non-I7":                   func(p *networkOnlyDriverProof) { p.choiceOn = false },
		"cached enabled without same-process owner": func(p *networkOnlyDriverProof) { p.ownerScope = false },
		"unproven or wrong descriptor root":         func(p *networkOnlyDriverProof) { p.descriptorBound = false },
		"missing or unhealthy official binding":     func(p *networkOnlyDriverProof) { p.officialHealthy = false },
		"foreign or reparse store":                  func(p *networkOnlyDriverProof) { p.storeProtected = false },
		"missing corrupt service receipt":           func(p *networkOnlyDriverProof) { p.receiptValid = false },
		"empty or other root receipt":               func(p *networkOnlyDriverProof) { p.receiptOwnsRoot = false },
		"service missing or unreadable":             func(p *networkOnlyDriverProof) { p.serviceReadable = false },
		"root native state changed":                 func(p *networkOnlyDriverProof) { p.rootNativeHealthy = false },
		"service restarted externally":              func(p *networkOnlyDriverProof) { p.serviceState = 4 },
		"service pending":                           func(p *networkOnlyDriverProof) { p.serviceState = 2 },
		"service startup changed externally":        func(p *networkOnlyDriverProof) { p.serviceStart = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := valid
			breakProof(&bad)
			if bad.admitsExpectedStop() {
				t.Fatal("incomplete isolation proof admitted stopped service")
			}
		})
	}
}

func TestFirstNetworkOnlyApplyRequiresConfirmedMissingReceiptAndFreshStableOriginal(t *testing.T) {
	p := networkOnlyDriverProof{choiceOn: true, ownerScope: true, descriptorBound: true, officialHealthy: true, storeProtected: true, serviceReadable: true, rootNativeHealthy: true, serviceState: 4, serviceStart: 2}
	if !p.admitsInitialApply(true) || p.admitsExpectedStop() {
		t.Fatal("first stage5 running original not admitted distinctly from an expected stop")
	}
	if p.admitsInitialApply(false) {
		t.Fatal("corrupt/partial/existing receipt became first apply")
	}
	for name, corrupt := range map[string]func(*networkOnlyDriverProof){
		"existing receipt":      func(p *networkOnlyDriverProof) { p.receiptValid = true },
		"existing owned root":   func(p *networkOnlyDriverProof) { p.receiptOwnsRoot = true },
		"memory-only enabled":   func(p *networkOnlyDriverProof) { p.ownerScope = false },
		"missing service":       func(p *networkOnlyDriverProof) { p.serviceReadable = false },
		"unknown service state": func(p *networkOnlyDriverProof) { p.serviceState = 0 },
		"pending service state": func(p *networkOnlyDriverProof) { p.serviceState = 2 },
		"invalid startup type":  func(p *networkOnlyDriverProof) { p.serviceStart = 5 },
		"wrong root":            func(p *networkOnlyDriverProof) { p.descriptorBound = false },
		"unhealthy root":        func(p *networkOnlyDriverProof) { p.rootNativeHealthy = false },
		"off choice":            func(p *networkOnlyDriverProof) { p.choiceOn = false },
		"foreign store":         func(p *networkOnlyDriverProof) { p.storeProtected = false },
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			corrupt(&bad)
			if bad.admitsInitialApply(true) {
				t.Fatal("invalid initial scope admitted")
			}
		})
	}
}

func TestDriverAdmissionBindsActualOwnerAndOwnedPortableReceiptToSameRoot(t *testing.T) {
	root := `USB\VID_05AC&PID_12AB\ABC123456789`
	other := `USB\VID_05AC&PID_12AB\OTHER123456789`
	if !networkOnlyDriverOwnerMatches(5, root, true, strings.ToLower(root), true, root) {
		t.Fatal("exact casefold owner rejected")
	}
	for _, bad := range []struct {
		stage         int
		scope, proof  string
		ready, proved bool
	}{{0, root, root, true, true}, {5, other, root, true, true}, {5, root, other, true, true}, {5, root, root, false, true}, {5, root, root, true, false}} {
		if networkOnlyDriverOwnerMatches(bad.stage, bad.scope, bad.ready, bad.proof, bad.proved, root) {
			t.Fatal("foreign/unproven owner admitted")
		}
	}
	n := portableNodeReceipt{Root: root, ID: `USB\VID_05AC&PID_12AB&MI_00\CHILD`, Class: portableWPDClass}
	if !networkOnlyDriverReceiptOwnsRoot([]portableNodeReceipt{n}, root) {
		t.Fatal("owned same-root receipt rejected")
	}
	if networkOnlyDriverReceiptOwnsRoot(nil, root) || networkOnlyDriverReceiptOwnsRoot([]portableNodeReceipt{n}, other) {
		t.Fatal("empty/foreign receipt granted isolation")
	}
	n.Class = "unrelated-class"
	if networkOnlyDriverReceiptOwnsRoot([]portableNodeReceipt{n}, root) {
		t.Fatal("corrupt portable receipt admitted")
	}
}

func TestDriverAdmissionRequiresStartedNormalNativeRootAndReadableFlags(t *testing.T) {
	if !networkOnlyDriverNativeHealthy(0x0180600a, 0, 0, true) {
		t.Fatal("normal started root rejected")
	}
	for _, bad := range []struct {
		status, problem, flags uint32
		readable               bool
	}{{0, 0, 0, true}, {0x0180600a, 22, 0, true}, {0x0180600a, 0, 1, true}, {0x0180600a | 0x100, 0, 0, true}, {0x0180600a | 0x40000, 0, 0, true}, {0x0180600a, 0, 0, false}} {
		if networkOnlyDriverNativeHealthy(bad.status, bad.problem, bad.flags, bad.readable) {
			t.Fatal("abnormal native root admitted", bad)
		}
	}
}

func TestDriverAdmissionChoiceCannotPromoteOffUnknownOrMalformedPreferences(t *testing.T) {
	if !networkOnlyDriverChoice([]byte(`{"version":1,"enabled":true}`)) {
		t.Fatal("explicit on rejected")
	}
	for _, data := range []string{``, `{}`, `{"version":1,"enabled":false}`, `{"version":2,"enabled":true}`, `{"version":1,"enabled":true,"cached_native_proof":true}`, `{"version":1,"enabled":true} {}`, `{"version":1,"enabled":true`, `{"version":1,"enabled":"true"}`} {
		if networkOnlyDriverChoice([]byte(data)) {
			t.Fatal("invalid/off choice admitted", data)
		}
	}
}
