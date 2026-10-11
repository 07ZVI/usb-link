package securitypolicy

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func topology() []DeviceNode {
	return []DeviceNode{
		{ID: `USB\VID_05AC&PID_1903\PEER`},
		{ID: `USB\VID_05AC&PID_1903&MI_00\NET`, Parent: `USB\VID_05AC&PID_1903\PEER`},
		{ID: `USB\VID_1234&PID_1234\KEY`, ClassGUID: KeyboardClass},
	}
}

func TestUSBAdmissionExactTopologyAndAllInputSignals(t *testing.T) {
	root := topology()[0].ID
	if v := USBAdmission(root, topology(), true); !v.Admit {
		t.Fatal(v)
	}
	for name, input := range map[string]DeviceNode{
		"hid-class": {ClassGUID: HIDClass}, "keyboard-class": {ClassGUID: KeyboardClass},
		"mouse-class": {ClassGUID: MouseClass}, "keyboard-service": {Service: "kbdhid"},
		"unbound-hid":    {CompatibleIDs: []string{`USB\Class_03&SubClass_01&Prot_01`}},
		"hid-collection": {CompatibleIDs: []string{"HID_DEVICE_SYSTEM_KEYBOARD"}},
	} {
		t.Run(name, func(t *testing.T) {
			input.ID = `HID\VID_05AC&PID_1903\INPUT`
			input.Parent = topology()[1].ID
			nodes := append(topology(), input)
			v := USBAdmission(root, nodes, true)
			if v.Admit || v.Code != "USB_UNEXPECTED_HID_INTERFACE" || v.InputNodes != 1 {
				t.Fatal(v)
			}
			// Same claimed VID/PID, different physical tree must not be quarantined.
			nodes[len(nodes)-1].Parent = `USB\VID_1234&PID_1234\KEY`
			if v = USBAdmission(root, nodes, true); !v.Admit {
				t.Fatal(v)
			}
		})
	}
}

func TestUSBAdmissionIncompleteDuplicateAndCyclicInputAncestry(t *testing.T) {
	nodes := topology()
	for _, complete := range []bool{false, true} {
		bad := nodes
		if complete {
			bad = append(bad, nodes[0])
		}
		if v := USBAdmission(nodes[0].ID, bad, complete); v.Admit {
			t.Fatal(v)
		}
	}
	nodes[2].Parent = nodes[2].ID
	if v := USBAdmission(nodes[0].ID, nodes, true); v.Code != "USB_SECURITY_ANCESTRY_UNAVAILABLE" {
		t.Fatal(v)
	}
	if v := USBAdmission(`USB\MISSING`, topology(), true); v.Code != "USB_SECURITY_ROOT_ABSENT" {
		t.Fatal(v)
	}
}

func TestWholeHostHIDBaselineIncludesBuiltInAndCompositeInputs(t *testing.T) {
	nodes := []DeviceNode{
		{ID: `ACPI\PNP0303\0`, ClassGUID: KeyboardClass},
		{ID: `HID\I2C\TOUCHPAD`, ClassGUID: HIDClass},
		{ID: `HID\USB\MOUSE`, ClassGUID: MouseClass},
		{ID: `USB\NCM\0`, Service: "UsbNcm"},
	}
	p, err := PlanHID(nodes, true)
	if err != nil || len(p.AllowedInstances) != 3 || !p.LayeredEvaluation || p.ApplyToInstalled {
		t.Fatal(p, err)
	}
	for _, entry := range p.AllowedInstances {
		if entry == `USB\NCM\0` {
			t.Fatal("network device got an input exception")
		}
	}
	if _, err = PlanHID(nodes, false); err == nil {
		t.Fatal("partial baseline accepted")
	}
	if _, err = PlanHID(nodes[1:], true); err == nil {
		t.Fatal("no recovery keyboard")
	}
	nodes[0].ID = `USB\*`
	if _, err = PlanHID(nodes, true); err == nil {
		t.Fatal("wildcard accepted")
	}
}

func TestExistingInputCannotBeRetroactivelyDisabled(t *testing.T) {
	p := fixturePlan(t)
	if !p.Valid() || p.ApplyToInstalled {
		t.Fatal(p)
	}
	p.ApplyToInstalled = true
	if p.Valid() {
		t.Fatal("retroactive input isolation accepted")
	}
	f := &transactionFixture{}
	if _, err := InstallHID(context.Background(), context.Background(), f, f, p); err == nil || len(f.trace) != 0 {
		t.Fatal("unsafe plan reached executor", err, f.trace)
	}
}

type transactionFixture struct {
	trace     []string
	fail      string
	enforced  bool
	cancelled bool
}

func (f *transactionFixture) Prepare(context.Context, HIDPlan) (Receipt, error) {
	f.trace = append(f.trace, "prepare")
	if f.fail == "conflict" {
		return Receipt{}, errors.New("foreign policy")
	}
	return Receipt{ID: "owned", Version: 1}, nil
}
func (f *transactionFixture) Apply(context.Context, Receipt) error {
	f.trace = append(f.trace, "apply")
	if f.fail == "apply" {
		return errors.New("partial apply")
	}
	return nil
}
func (f *transactionFixture) Verify(context.Context, Receipt) (Evidence, error) {
	f.trace = append(f.trace, "verify")
	return Evidence{State: Verified, Scope: "host", EnforcementVerified: f.enforced}, nil
}
func (f *transactionFixture) Restore(ctx context.Context, _ Receipt) error {
	f.trace = append(f.trace, "restore")
	f.cancelled = ctx.Err() != nil
	if f.fail == "restore" {
		return errors.New("ownership changed")
	}
	return nil
}
func (f *transactionFixture) SavePending(Receipt) error {
	f.trace = append(f.trace, "journal")
	if f.fail == "journal" {
		return errors.New("disk full")
	}
	return nil
}
func (f *transactionFixture) Clear(Receipt) error { f.trace = append(f.trace, "clear"); return nil }

func TestHostTransactionSaveBeforeMutationAndPreserveRecovery(t *testing.T) {
	for _, c := range []struct {
		name     string
		enforced bool
		trace    []string
		ok       bool
	}{
		{"success", true, []string{"prepare", "journal", "apply", "verify"}, true},
		{"conflict", false, []string{"prepare"}, false},
		{"journal", false, []string{"prepare", "journal"}, false},
		{"apply", false, []string{"prepare", "journal", "apply", "restore", "clear"}, false},
		{"unconfirmed", false, []string{"prepare", "journal", "apply", "verify", "restore", "clear"}, false},
		{"restore", false, []string{"prepare", "journal", "apply", "verify", "restore"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &transactionFixture{fail: c.name, enforced: c.enforced}
			e, err := InstallHID(context.Background(), context.Background(), f, f, fixturePlan(t))
			if (err == nil) != c.ok || !reflect.DeepEqual(f.trace, c.trace) {
				t.Fatal(e, err, f.trace)
			}
			if c.name == "restore" && e.Code != "SECURITY_RECOVERY_REQUIRED" {
				t.Fatal(e)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &transactionFixture{}
	_, err := InstallHID(ctx, context.Background(), f, f, fixturePlan(t))
	if err == nil || f.cancelled || !reflect.DeepEqual(f.trace, []string{"prepare", "journal", "restore", "clear"}) {
		t.Fatal(err, f)
	}
}

func TestServiceCataloguePreservesTransportBoundaries(t *testing.T) {
	if Ports(FileAndSpeed, "TCP") != "10690" || Ports(DeveloperUpgrade, "TCP") != "47775" {
		t.Fatal("public ports changed")
	}
	if InboundPorts("ipad", "TCP") != "10690,47984,47989,48010" || InboundPorts("mac", "TCP") != "47984,47989,47990,48010" {
		t.Fatal("migration changed exceptions")
	}
	if Ports("arbitrary", "TCP") != "" || InboundPorts("surface", "TCP") != "" || Ports(DeveloperUpgrade, "UDP") != "" {
		t.Fatal("unknown service allowed")
	}
}

func fixturePlan(t *testing.T) HIDPlan {
	t.Helper()
	p, err := PlanHID(topology(), true)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHostTransactionRejectsPlanWithNoRecoveryInputBeforeAnyWork(t *testing.T) {
	f := &transactionFixture{}
	p := fixturePlan(t)
	p.RecoveryKeyboardInstance = ""
	if _, err := InstallHID(context.Background(), context.Background(), f, f, p); err == nil || len(f.trace) != 0 {
		t.Fatal(err, f.trace)
	}
}
