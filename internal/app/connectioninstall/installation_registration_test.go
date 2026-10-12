package connectioninstall

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type registrationFixture struct {
	values       map[string]registrationValue
	failName     string
	failed       bool
	badReadback  bool
	writes       int
	flushFailure bool
}

func cloneRegValue(v registrationValue) registrationValue {
	v.Data = append([]byte(nil), v.Data...)
	return v
}
func (f *registrationFixture) Read(name string) (registrationValue, error) {
	v := cloneRegValue(f.values[name])
	if f.badReadback && f.writes >= 9 && name == "NoRepair" {
		v = registrationDWORD(0)
	}
	return v, nil
}
func (f *registrationFixture) Write(name string, v registrationValue) error {
	f.writes++
	f.values[name] = cloneRegValue(v)
	if name == f.failName && !f.failed {
		f.failed = true
		return errors.New("setter changed value then failed")
	}
	return nil
}
func (f *registrationFixture) Remove(name string) error { delete(f.values, name); return nil }
func (f *registrationFixture) Sync() error {
	if f.flushFailure {
		f.flushFailure = false
		return errors.New("flush failed")
	}
	return nil
}
func regPlan() map[string]registrationValue {
	m := map[string]registrationValue{}
	for _, n := range registrationNames {
		m[n] = registrationString("new " + n)
	}
	m["NoModify"] = registrationDWORD(1)
	m["NoRepair"] = registrationDWORD(1)
	return m
}
func TestEveryRegistrationSetterFailureRestoresOriginalValues(t *testing.T) {
	for _, name := range registrationNames {
		before := map[string]registrationValue{"DisplayVersion": registrationString("old"), "NoRepair": registrationDWORD(0), "Unknown": registrationString("retain")}
		values := map[string]registrationValue{}
		for n, v := range before {
			values[n] = cloneRegValue(v)
		}
		f := &registrationFixture{values: values, failName: name}
		if e := writeInstallationRegistration(f, regPlan()); e == nil {
			t.Fatal("setter failure ignored", name)
		}
		if !reflect.DeepEqual(before, f.values) {
			t.Fatalf("%s failed to restore old values: %#v", name, f.values)
		}
	}
}
func TestRegistrationReadbackAndFlushFailuresCannotReportSuccess(t *testing.T) {
	for _, kind := range []string{"readback", "flush"} {
		f := &registrationFixture{values: map[string]registrationValue{}, badReadback: kind == "readback", flushFailure: kind == "flush"}
		e := writeInstallationRegistration(f, regPlan())
		if e == nil || len(f.values) != 0 {
			t.Fatal(kind, e, f.values)
		}
		if kind == "readback" && !strings.Contains(e.Error(), "READBACK_FAILED") {
			t.Fatal(e)
		}
	}
	f := &registrationFixture{values: map[string]registrationValue{}}
	if e := writeInstallationRegistration(f, regPlan()); e != nil || !reflect.DeepEqual(f.values, regPlan()) {
		t.Fatal(e, f.values)
	}
}
