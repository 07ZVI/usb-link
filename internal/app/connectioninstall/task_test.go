package connectioninstall

import (
	"encoding/xml"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestTaskEscapesAndScopesStartup(t *testing.T) {
	s, e := TaskXML(`C:\Program Files\A&B\Suhang-iPad-USB.exe`, "S-1-5-21-1-2-3-1001")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Description string                              `xml:"RegistrationInfo>Description"`
		Principal   string                              `xml:"Principals>Principal>UserId"`
		Action      struct{ Command, Arguments string } `xml:"Actions>Exec"`
	}
	if xml.Unmarshal([]byte(s), &v) != nil || v.Description != ProductID || v.Principal != "S-1-5-21-1-2-3-1001" || v.Action.Command != `C:\Program Files\A&B\Suhang-iPad-USB.exe` || v.Action.Arguments != "--resident" || !strings.Contains(s, "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>") {
		t.Fatal(s)
	}
	if _, e = TaskXML("x", "everyone"); e == nil {
		t.Fatal("unscoped principal")
	}
}

func TestBrandInstallPathsStayPaired(t *testing.T) {
	for _, tc := range []struct {
		parent, name string
		want         bool
	}{
		{"new", BinaryName, true}, {"old", LegacyBinaryName, true}, {"NEW", BinaryName, true},
		{"old", BinaryName, false}, {"new", LegacyBinaryName, false}, {"foreign", BinaryName, false},
	} {
		if validInstallLocation(tc.parent, tc.name, "new", "old") != tc.want {
			t.Errorf("incorrect ownership for %s/%s", tc.parent, tc.name)
		}
	}
}

func TestTaskXMLIsEncodingNeutralUnicodePayload(t *testing.T) {
	path := `C:\Program Files\USB Link\0.8.92\試験 & café 😀\USB-Link.exe`
	sid := "S-1-5-21-1-2-3-1001"
	payload, err := TaskXML(path, sid)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(payload, `<?xml version="1.0"?>`) || strings.Contains(payload, "encoding=") {
		t.Fatal("byte encoding declaration in Unicode BSTR payload")
	}
	// Windows passes this value as a Unicode string. Non-ASCII and XML
	// metacharacters must survive the boundary and decode to the exact action.
	wide := utf16.Encode([]rune(payload))
	decoded := string(utf16.Decode(wide))
	var task struct {
		XMLName     xml.Name
		Version     string `xml:"version,attr"`
		Description string `xml:"RegistrationInfo>Description"`
		Principal   struct {
			ID       string `xml:"id,attr"`
			UserID   string `xml:"UserId"`
			Logon    string `xml:"LogonType"`
			RunLevel string `xml:"RunLevel"`
		} `xml:"Principals>Principal"`
		Trigger struct {
			Enabled bool   `xml:"Enabled"`
			UserID  string `xml:"UserId"`
			Delay   string `xml:"Delay"`
		} `xml:"Triggers>LogonTrigger"`
		Actions struct {
			Context string `xml:"Context,attr"`
			Exec    struct {
				Command   string
				Arguments string
			}
		} `xml:"Actions"`
		Settings struct {
			Instances     string `xml:"MultipleInstancesPolicy"`
			HardTerminate bool   `xml:"AllowHardTerminate"`
			Limit         string `xml:"ExecutionTimeLimit"`
			Enabled       bool   `xml:"Enabled"`
		} `xml:"Settings"`
	}
	if err := xml.Unmarshal([]byte(decoded), &task); err != nil {
		t.Fatal(err)
	}
	if task.XMLName.Local != "Task" || task.XMLName.Space != "http://schemas.microsoft.com/windows/2004/02/mit/task" || task.Version != "1.2" || task.Description != ProductID || task.Principal.ID != "Owner" || task.Principal.UserID != sid || task.Principal.Logon != "InteractiveToken" || task.Principal.RunLevel != "HighestAvailable" || !task.Trigger.Enabled || task.Trigger.UserID != sid || task.Trigger.Delay != "PT5S" || task.Actions.Context != task.Principal.ID || task.Actions.Exec.Command != path || task.Actions.Exec.Arguments != "--resident" || task.Settings.Instances != "IgnoreNew" || task.Settings.HardTerminate || task.Settings.Limit != "PT0S" || !task.Settings.Enabled {
		t.Fatal("task Unicode boundary changed action or authorization policy")
	}
}
