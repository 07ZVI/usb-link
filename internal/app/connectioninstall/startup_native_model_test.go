package connectioninstall

import (
	"errors"
	"strings"
	"testing"
)

func TestNativeTaskFullScope(t *testing.T) {
	sid := "S-1-5-21-1-2-3-4"
	x, _ := TaskXML(`C:\Program Files\USB Link\0.8.98\USB-Link.exe`, sid)
	base := nativeStartupTask{XML: x, State: 3, Enabled: true}
	resolve := func(s string) (string, error) {
		if s != sid {
			return "", errors.New("foreign")
		}
		return s, nil
	}
	verify := func(s string) error {
		if s != `C:\Program Files\USB Link\0.8.98\USB-Link.exe` {
			return errors.New("foreign")
		}
		return nil
	}
	good, e := parseNativeStartupTask(base, sid, resolve, verify)
	if e != nil || !good.Enabled {
		t.Fatalf("valid task %v", e)
	}
	for _, change := range [][2]string{{ProductID, "other"}, {"InteractiveToken", "Password"}, {"HighestAvailable", "LeastPrivilege"}, {"--resident", "--other"}, {"PT5S", "PT0S"}, {"<Enabled>true</Enabled>", "<Enabled>bad</Enabled>"}, {"<Exec>", "<ComHandler>"}, {"</Actions>", "<Exec><Command>evil</Command></Exec></Actions>"}, {"</Triggers>", "<TimeTrigger/></Triggers>"}, {sid, "S-1-5-21-9-9-9-9"}} {
		v := base
		v.XML = strings.ReplaceAll(x, change[0], change[1])
		if _, e := parseNativeStartupTask(v, sid, resolve, verify); e == nil {
			t.Errorf("accepted change %q", change[1])
		}
	}
	v := base
	v.State = 0
	if _, e := parseNativeStartupTask(v, sid, resolve, verify); e == nil {
		t.Fatal("unknown state")
	}
	v = base
	v.XML = strings.Replace(x, `<?xml version="1.0"?>`, `<?xml version="1.0" encoding="UTF-16"?>`, 1)
	if _, e := parseNativeStartupTask(v, sid, resolve, verify); e != nil {
		t.Fatal("COM Unicode declaration", e)
	}
}

func TestNativeTaskAcceptsSchedulerDefaultEnabledWithoutChangingOwnership(t *testing.T) {
	sid := "S-1-5-21-1-2-3-4"
	path := `C:\Program Files\USB Link\0.8.97\USB-Link.exe`
	x, _ := TaskXML(path, sid)
	resolve := func(s string) (string, error) {
		if s != sid {
			return "", errors.New("foreign")
		}
		return s, nil
	}
	verify := func(s string) error {
		if s != path {
			return errors.New("foreign")
		}
		return nil
	}
	trigger := `<LogonTrigger><Enabled>true</Enabled>`
	settings := `<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled>`
	for name, xmlText := range map[string]string{
		"trigger_default":  strings.Replace(x, trigger, `<LogonTrigger>`, 1),
		"settings_default": strings.Replace(x, settings, `<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>`, 1),
		"both_defaults":    strings.ReplaceAll(x, `<Enabled>true</Enabled>`, ""),
	} {
		t.Run(name, func(t *testing.T) {
			base := nativeStartupTask{XML: xmlText, State: 3, Enabled: true}
			got, e := parseNativeStartupTask(base, sid, resolve, verify)
			if e != nil || !got.Enabled || got.Command != path || got.TriggerObservation == nil || !got.TriggerObservation.Available || !got.TriggerObservation.UserIDMatches || got.TriggerObservation.Delay != "PT5S" {
				t.Fatalf("scheduler default rejected: %v %+v", e, got)
			}
			base.Enabled = false
			got, e = parseNativeStartupTask(base, sid, resolve, verify)
			if e != nil || got.Enabled {
				t.Fatal("XML defaults overrode native disabled task", e)
			}
			for _, change := range [][2]string{{sid, "S-1-5-21-9-8-7-6"}, {path, `C:\foreign.exe`}, {"InteractiveToken", "Password"}, {"HighestAvailable", "LeastPrivilege"}, {"PT5S", "PT0S"}, {"--resident", "--other"}, {"LogonTrigger", "BootTrigger"}} {
				v := base
				v.XML = strings.ReplaceAll(xmlText, change[0], change[1])
				if _, e := parseNativeStartupTask(v, sid, resolve, verify); e == nil {
					t.Fatalf("default accepted foreign change %q", change[1])
				}
			}
		})
	}
	for _, xmlText := range []string{strings.Replace(x, trigger, `<LogonTrigger><Enabled>false</Enabled>`, 1), strings.Replace(x, settings, `<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>false</Enabled>`, 1)} {
		got, e := parseNativeStartupTask(nativeStartupTask{XML: xmlText, State: 3, Enabled: true}, sid, resolve, verify)
		if e != nil || got.Enabled {
			t.Fatal("explicit disabled state was not retained", e)
		}
	}
}

func TestNativeTriggerObservationIsBoundedAndOwnershipGated(t *testing.T) {
	sid := "S-1-5-21-1-2-3-4"
	path := `C:\Program Files\USB Link\0.8.97\USB-Link.exe`
	x, _ := TaskXML(path, sid)
	resolve := func(s string) (string, error) {
		if s != sid {
			return "", errors.New("foreign")
		}
		return sid, nil
	}
	verify := func(s string) error {
		if s != path {
			return errors.New("foreign")
		}
		return nil
	}
	for _, change := range [][2]string{{ProductID, "foreign"}, {path, `C:\foreign.exe`}, {"HighestAvailable", "LeastPrivilege"}, {"InteractiveToken", "Password"}, {"--resident", "--other"}} {
		v, e := parseNativeStartupTask(nativeStartupTask{XML: strings.ReplaceAll(x, change[0], change[1]), State: 3, Enabled: true}, sid, resolve, verify)
		if e == nil || v.TriggerObservation != nil {
			t.Fatal("unproven task leaked observation", change)
		}
	}
	for _, delay := range []string{`C:\Users\secret\record.xml`, strings.Repeat("P", 65), "S-1-5-21-1-2-3-4"} {
		v, e := parseNativeStartupTask(nativeStartupTask{XML: strings.Replace(x, "PT5S", delay, 1), State: 3, Enabled: true}, sid, resolve, verify)
		if e == nil || v.TriggerObservation == nil || v.TriggerObservation.Delay != "<invalid>" {
			t.Fatal("unsafe delay diagnostic", e, v.TriggerObservation)
		}
	}
	if nativeTriggerName("private-device-name") != "other" {
		t.Fatal("unbounded trigger name")
	}
	v, e := parseNativeStartupTask(nativeStartupTask{XML: strings.Replace(x, "PT5S", "PT0H0M5S", 1), State: 3, Enabled: true}, sid, resolve, verify)
	if e == nil || v.TriggerObservation == nil || v.TriggerObservation.Delay != "PT0H0M5S" {
		t.Fatal("unexpected duration normalized without evidence", e, v.TriggerObservation)
	}
}

func TestHistoricalStartupSourceRequiresOriginalActivationShape(t *testing.T) {
	sid := "S-1-5-21-1-2-3-4"
	x, _ := TaskXML(`C:\Program Files\USB Link\0.8.97\USB-Link.exe`, sid)
	if !nativeHistoricalTaskShape(x) {
		t.Fatal("original task shape rejected")
	}
	for _, change := range [][2]string{
		{`id="Owner"`, `id="Foreign"`}, {`Context="Owner"`, `Context="Foreign"`},
		{`</LogonTrigger>`, `<StartBoundary>2026-10-09T00:00:00</StartBoundary></LogonTrigger>`},
		{`</LogonTrigger>`, `<EndBoundary>2026-10-10T00:00:00</EndBoundary></LogonTrigger>`},
		{`</LogonTrigger>`, `<Repetition><Interval>PT1M</Interval></Repetition></LogonTrigger>`},
		{`</LogonTrigger>`, `<ExecutionTimeLimit>PT1S</ExecutionTimeLimit></LogonTrigger>`},
		{`</Triggers>`, `<LogonTrigger/></Triggers>`},
		{`</Task>`, `</Task><Task/>`},
	} {
		if nativeHistoricalTaskShape(strings.Replace(x, change[0], change[1], 1)) {
			t.Fatalf("historical schedule/context accepted %q", change[1])
		}
	}
	for _, xmlText := range []string{strings.ReplaceAll(x, `<Enabled>true</Enabled>`, ""), strings.Replace(x, `</LogonTrigger>`, `<ExecutionTimeLimit>PT72H</ExecutionTimeLimit></LogonTrigger>`, 1)} {
		if !nativeHistoricalTaskShape(xmlText) {
			t.Fatal("schema default changed original scope")
		}
	}
}
