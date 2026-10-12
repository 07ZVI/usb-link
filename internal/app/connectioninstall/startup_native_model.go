package connectioninstall

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

type nativeStartupDefinition struct {
	XMLName      xml.Name
	Registration struct{ Description string } `xml:"RegistrationInfo"`
	Principals   struct {
		Items []struct {
			ID        string `xml:"id,attr"`
			UserID    string `xml:"UserId"`
			LogonType string
			RunLevel  string
		} `xml:"Principal"`
	}
	Triggers struct {
		Items []struct {
			XMLName            xml.Name
			UserID             string `xml:"UserId"`
			Delay              string
			Enabled            *bool
			StartBoundary      string
			EndBoundary        string
			Repetition         *struct{}
			ExecutionTimeLimit string
		} `xml:",any"`
	}
	Settings struct{ Enabled *bool }
	Actions  struct {
		Context string `xml:"Context,attr"`
		Items   []struct {
			XMLName          xml.Name
			Command          string
			Arguments        string
			WorkingDirectory string
		} `xml:",any"`
	}
}

// A missing historical source must not grant an altered activation schedule.
func nativeHistoricalTaskShape(text string) bool {
	var d nativeStartupDefinition
	dec := nativeTaskDecoder(text)
	if dec.Decode(&d) != nil || dec.Decode(new(any)) != io.EOF || len(d.Principals.Items) != 1 || len(d.Triggers.Items) != 1 || d.Principals.Items[0].ID != "Owner" || d.Actions.Context != "Owner" {
		return false
	}
	t := d.Triggers.Items[0]
	return t.StartBoundary == "" && t.EndBoundary == "" && t.Repetition == nil && (t.ExecutionTimeLimit == "" || t.ExecutionTimeLimit == "PT72H")
}

type nativeStartupTask struct {
	Name, Path, XML, Command string
	State                    int32
	Enabled                  bool
	TriggerObservation       *NativeStartupTriggerObservation
	InspectionProblem        string
}

// Fixed sanitized observation only. The producer attaches it after description,
// principal, action and installed source have passed; it never grants ownership.
type NativeStartupTriggerObservation struct {
	ObservationOnly         bool   `json:"observation_only"`
	Available               bool   `json:"available"`
	TriggerCount            int    `json:"trigger_count"`
	TriggerName             string `json:"trigger_name,omitempty"`
	TriggerNamespaceMatches bool   `json:"trigger_namespace_matches"`
	UserIDMatches           bool   `json:"user_id_matches"`
	Delay                   string `json:"delay,omitempty"`
	TriggerEnabledPresent   bool   `json:"trigger_enabled_present"`
	TriggerEnabledValue     bool   `json:"trigger_enabled_value"`
	SettingsEnabledPresent  bool   `json:"settings_enabled_present"`
	SettingsEnabledValue    bool   `json:"settings_enabled_value"`
}

func nativeTaskEnabled(v *bool) bool { return v == nil || *v }
func nativeTriggerName(name string) string {
	switch name {
	case "LogonTrigger", "BootTrigger", "CalendarTrigger", "IdleTrigger", "EventTrigger", "TimeTrigger", "RegistrationTrigger", "SessionStateChangeTrigger":
		return name
	}
	return "other"
}
func nativeTriggerDelay(delay string) string {
	if len(delay) == 0 {
		return "<absent>"
	}
	if len(delay) > 64 || !strings.HasPrefix(delay, "P") || strings.Trim(delay, "0123456789PTYMDHS.") != "" {
		return "<invalid>"
	}
	return delay
}

const taskNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task"

// COM Xml is already a Unicode string. A UTF-16 declaration describes its
// original BSTR, not the UTF-8 bytes used by Go's XML decoder.
func parseNativeStartupTask(t nativeStartupTask, sid string, resolve func(string) (string, error), verify func(string) error) (nativeStartupTask, error) {
	fail := func(code string) (nativeStartupTask, error) { return t, errors.New(code) }
	if len(t.XML) == 0 || len(t.XML) > 65536 || strings.Contains(t.XML, "<!") || !nativeTaskXMLUnique(t.XML) {
		return fail("STARTUP_XML_INVALID")
	}
	var d nativeStartupDefinition
	dec := xml.NewDecoder(strings.NewReader(t.XML))
	dec.CharsetReader = func(label string, r io.Reader) (io.Reader, error) {
		if strings.EqualFold(label, "utf-16") {
			return r, nil
		}
		return nil, errors.New("STARTUP_XML_INVALID")
	}
	if dec.Decode(&d) != nil || dec.Decode(new(any)) != io.EOF || d.XMLName.Local != "Task" || d.XMLName.Space != taskNamespace {
		return fail("STARTUP_XML_INVALID")
	}
	if d.Registration.Description != ProductID {
		return fail("STARTUP_TASK_OWNERSHIP_CHANGED")
	}
	if len(d.Principals.Items) != 1 {
		return fail("STARTUP_PRINCIPAL_CHANGED")
	}
	p := d.Principals.Items[0]
	who, e := resolve(p.UserID)
	if e != nil || who != sid {
		return fail("STARTUP_PRINCIPAL_CHANGED")
	}
	if p.LogonType != "InteractiveToken" {
		return fail("STARTUP_TASK_LOGON_TYPE_CHANGED")
	}
	if p.RunLevel != "HighestAvailable" {
		return fail("STARTUP_TASK_RUN_LEVEL_CHANGED")
	}
	if len(d.Actions.Items) != 1 {
		return fail("STARTUP_TASK_ACTION_CHANGED")
	}
	a := d.Actions.Items[0]
	if a.XMLName.Local != "Exec" || a.XMLName.Space != taskNamespace || a.Arguments != "--resident" || a.WorkingDirectory != "" || a.Command == "" {
		return fail("STARTUP_TASK_ACTION_CHANGED")
	}
	t.Command = a.Command
	if verify(a.Command) != nil {
		return fail("STARTUP_TASK_RECEIPT_CHANGED")
	}
	observation := &NativeStartupTriggerObservation{
		ObservationOnly: true, Available: true, TriggerCount: len(d.Triggers.Items),
		SettingsEnabledPresent: d.Settings.Enabled != nil,
		SettingsEnabledValue:   nativeTaskEnabled(d.Settings.Enabled),
	}
	t.TriggerObservation = observation
	if len(d.Triggers.Items) != 1 {
		return fail("STARTUP_TASK_TRIGGER_CHANGED")
	}
	tr := d.Triggers.Items[0]
	who, e = resolve(tr.UserID)
	observation.TriggerName = nativeTriggerName(tr.XMLName.Local)
	observation.TriggerNamespaceMatches = tr.XMLName.Space == taskNamespace
	observation.UserIDMatches = e == nil && who == sid
	observation.Delay = nativeTriggerDelay(tr.Delay)
	observation.TriggerEnabledPresent = tr.Enabled != nil
	observation.TriggerEnabledValue = nativeTaskEnabled(tr.Enabled)
	if tr.XMLName.Local != "LogonTrigger" || tr.XMLName.Space != taskNamespace || e != nil || who != sid || tr.Delay != "PT5S" {
		return fail("STARTUP_TASK_TRIGGER_CHANGED")
	}
	if t.State < 1 || t.State > 4 {
		return fail("STARTUP_TASK_STATE_UNKNOWN")
	}
	// Task Scheduler's schema defaults both optional Enabled elements to true.
	// A COM-normalized definition may omit them; explicit false and the native
	// registered-task Enabled/State observations still disable the task.
	t.Enabled = t.Enabled && nativeTaskEnabled(d.Settings.Enabled) && nativeTaskEnabled(tr.Enabled) && t.State != 1
	return t, nil
}

func nativeTaskDecoder(text string) *xml.Decoder {
	d := xml.NewDecoder(strings.NewReader(text))
	d.CharsetReader = func(label string, r io.Reader) (io.Reader, error) {
		if strings.EqualFold(label, "utf-16") {
			return r, nil
		}
		return nil, errors.New("STARTUP_XML_INVALID")
	}
	return d
}
func nativeTaskXMLUnique(text string) bool {
	d := nativeTaskDecoder(text)
	stack := []string{}
	seen := map[string]bool{}
	for {
		t, e := d.Token()
		if e == io.EOF {
			return len(stack) == 0
		}
		if e != nil {
			return false
		}
		switch v := t.(type) {
		case xml.StartElement:
			if v.Name.Space != taskNamespace || len(stack) > 16 {
				return false
			}
			stack = append(stack, v.Name.Local)
			p := strings.Join(stack, "/")
			unique := p == "Task" || p == "Task/RegistrationInfo" || p == "Task/Principals" || p == "Task/Triggers" || p == "Task/Settings" || p == "Task/Actions" || p == "Task/RegistrationInfo/Description" || strings.HasPrefix(p, "Task/Principals/Principal/") || strings.HasPrefix(p, "Task/Triggers/LogonTrigger/") || strings.HasPrefix(p, "Task/Actions/Exec/") || p == "Task/Settings/Enabled"
			if unique {
				if seen[p] {
					return false
				}
				seen[p] = true
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return false
			}
			stack = stack[:len(stack)-1]
		}
	}
}
