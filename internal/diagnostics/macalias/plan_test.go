package macalias

import "testing"

const fixture = `+-o AppleT8103USBXDCI@0  <class AppleT8103USBXDCI, id 1>
  | "CurrentState" = {"OnBus"=Yes,"DeviceState"="Configured"}
  +-o AppleUSBNCMData@1  <class IOUSBDeviceInterface, id 2>
  | +-o AppleUSBDeviceNCM11Data  <class AppleUSBDeviceNCM11Data, id 3>
  | | "BSD Name" = "en3"
  +-o AppleUSBNCMDataAux@3  <class IOUSBDeviceInterface, id 4>
  | | "BSD Name" = "anpi0"
+-o AppleT8103USBXDCI@1  <class AppleT8103USBXDCI, id 5>
  | "CurrentState" = {"OnBus"=No,"DeviceState"="Disconnected"}
  +-o AppleUSBNCMData@1  <class IOUSBDeviceInterface, id 6>
  | +-o AppleUSBDeviceNCM11Data  <class AppleUSBDeviceNCM11Data, id 7>
  | | "BSD Name" = "en4"`

func TestScope(t *testing.T) {
	v, e := Parse(fixture)
	if e != nil || len(v) != 2 || v[0].Name != "en3" || !v[0].Connected || v[1].Connected {
		t.Fatalf("%+v %v", v, e)
	}
	// A stray sibling with a BSD Name cannot replace a missing NCM interface.
	_, e = Parse(`+-o AppleT8103USBXDCI@0  <class AppleT8103USBXDCI, id 1>
  +-o AppleUSBNCMData@1  <class IOUSBDeviceInterface, id 2>
  +-o Other  <class Other, id 3>
  | "BSD Name" = "en0"`)
	if e == nil {
		t.Fatal("accepted arbitrary interface")
	}
}
func TestOwnershipAndSwitch(t *testing.T) {
	v, _ := Parse(fixture)
	a := []Address{{"en3", "10.77.0.1", "0xffffff00"}, {"en3", "169.254.9.2", "0xffff0000"}}
	if _, e := Plan(v, a, nil); e == nil {
		t.Fatal("adopted unknown address")
	}
	own := []Owned{{"0", "en3"}}
	p, e := Plan(v, a, own)
	if e != nil || len(p) != 0 {
		t.Fatalf("existing %+v %v", p, e)
	}
	v[0].Connected = false
	v[1].Connected = true
	p, e = Plan(v, a, own)
	if e != nil || len(p) != 2 || p[0].Add || p[0].Interface != "en3" || !p[1].Add || p[1].Interface != "en4" {
		t.Fatalf("switch %+v %v", p, e)
	}
	a = append(a, Address{"en0", "10.77.0.55", "0xffffff00"})
	if _, e := Plan(v, a, own); e == nil {
		t.Fatal("accepted subnet conflict")
	}
}
func TestAmbiguityAndForeignIPv4(t *testing.T) {
	v, _ := Parse(fixture)
	v[1].Connected = true
	if _, e := Plan(v, nil, nil); e == nil {
		t.Fatal("accepted two controllers")
	}
	v[1].Connected = false
	if _, e := Plan(v, []Address{{"en3", "192.168.1.1", "0xffffff00"}}, nil); e == nil {
		t.Fatal("overwrote IPv4")
	}
	if _, e := Plan(v, nil, []Owned{{"0", "en4"}}); e == nil {
		t.Fatal("mapping mismatch")
	}
	p, e := Plan(v, []Address{{"en3", "169.254.1.1", "0xffff0000"}}, nil)
	if e != nil || len(p) != 1 || !p[0].Add {
		t.Fatalf("linklocal %+v %v", p, e)
	}
}

func TestOverlappingForeignSubnet(t *testing.T) {
	v, _ := Parse(fixture)
	if _, e := Plan(v, []Address{{"en0", "10.77.5.8", "0xffff0000"}}, nil); e == nil {
		t.Fatal("accepted overlapping /16")
	}
	if _, e := Plan(v, []Address{{"en0", "192.168.5.8", "0xffffff00"}}, nil); e != nil {
		t.Fatal(e)
	}
}

func TestUnifiedMigrationOnlyChangesOwnedAliasAndResumesPartialUpdate(t *testing.T) {
	v, _ := Parse(fixture)
	owned := []Owned{{"0", "en3"}}
	old := []Address{{"en3", "10.77.0.1", "0xffffff00"}}
	p, e := MigrationPlan(v, old, owned)
	if e != nil || len(p) != 2 || p[0].Add || p[0].IP != "10.77.0.1" || !p[1].Add || p[1].IP != "10.6.9.2" {
		t.Fatal("bad migration", p, e)
	}
	if _, e = MigrationPlan(v, old, nil); e == nil {
		t.Fatal("unowned legacy alias adopted")
	}
	p, e = MigrationPlan(v, []Address{{"en3", "10.6.9.2", "0xffffff00"}}, owned)
	if e != nil || len(p) != 0 {
		t.Fatal("partial migration not idempotent", p, e)
	}
	old = append(old, Address{"en0", "10.6.9.99", "0xffffff00"})
	if _, e = MigrationPlan(v, old, owned); e == nil {
		t.Fatal("new subnet conflict ignored")
	}
	if _, e = MigrationPlan(v, nil, []Owned{{"1", "en3"}}); e == nil {
		t.Fatal("changed controller accepted")
	}
	v[0].Connected = false
	p, e = MigrationPlan(v, []Address{{"en3", "10.77.0.1", "0xffffff00"}}, owned)
	if e != nil || len(p) != 1 || p[0].Add {
		t.Fatal("offline migration touched another interface", p, e)
	}
}
