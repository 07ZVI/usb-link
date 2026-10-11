package connectioninstall

import (
	"strings"
	"testing"
)

func TestMeasurementBounds(t *testing.T) {
	id := strings.Repeat("a", 32)
	for _, v := range []struct {
		k  string
		s  int
		id string
		ok bool
	}{{"RESOURCESTART", 1800, id, true}, {"RESOURCEDETAIL", 120, id, true}, {"RESOURCEDETAIL", 121, id, false}, {"RESOURCESTART", 7201, id, false}, {"RESOURCESTART", 0, id, false}, {"RESOURCERESULT", 0, id, true}, {"RESOURCESTATUS", 1, id, false}, {"RESOURCEDELETE", 0, id, true}, {"RESOURCEDELETE", 1, id, false}, {"RESOURCEDELETE", 0, "../escape", false}, {"UDPSTART", 121, id, false}, {"UDPSTART", 120, id, true}, {"UDPSTOP", 0, id, true}, {"UICLOSE", 0, id, true}, {"UIOPEN", 0, id, true}, {"UICLOSE", 1, id, false}, {"UDPSTOP", 1, id, false}, {"cmd", 1, id, false}, {"RESOURCESTART", 60, "../escape", false}} {
		if (validMeasurement(v.k, v.s, v.id) == nil) != v.ok {
			t.Fatal(v)
		}
	}
}

func TestParentMeasurementBounds(t *testing.T) {
	id := strings.Repeat("a", 32)
	for _, v := range []struct {
		k  string
		s  int
		ok bool
	}{{"PARENTCPU", 30, true}, {"PARENTCPU", 31, false}, {"PARENTCPU", 0, false}, {"PARENTHEAP", 0, true}, {"PARENTHEAP", 1, false}, {"PARENTALLOCS", 0, true}, {"PARENTSTATE", 0, true}, {"PARENTGC800", 0, false}} {
		if (validMeasurement(v.k, v.s, id) == nil) != v.ok {
			t.Fatal(v)
		}
	}
}

func TestIPadDiagnosticIsFixedAndBounded(t *testing.T) {
	id := strings.Repeat("d", 32)
	for _, kind := range []string{"USBSTARTUPON", "USBHOSTSTARTUPSTATE", "IPADSIMPLIFIEDNATIVE", "IPADTRUSTRECYCLESELFTEST", "IPADUNPAIREDPREFLIGHT", "IPADUNPAIREDPREP", "IPADUNPAIREDSTATE", "IPADUNPAIREDFINISH", "IPADUNPAIREDREPLIED", "IPADAMDSRUNNING", "IPADAMDSSTOPPED", "IPADDIAGNOSTICRESULT", "IPADDIAGNOSTICCANCEL", "IPADDIAGNOSTICHOLD", "IPADSTARTUPSTATE", "IPADNETWORKONLYON", "IPADNETWORKONLYOFF", "IPADNETWORKONLYSTATE", "IPADNETWORKONLYPHASEON", "IPADNETWORKONLYPHASEOFF", "IPADCANDIDATE3", "IPADCANDIDATE41", "IPADCANDIDATE42", "IPADCANDIDATE43", "IPADCANDIDATE5", "IPADCANDIDATEDEFAULT", "IPADCANDIDATESTATE"} {
		if validMeasurement(kind, 0, id) != nil || validMeasurement(kind, 1, id) == nil || validMeasurement(kind, 0, "../escape") == nil {
			t.Fatal(kind)
		}
	}
	for _, kind := range []string{"USBSTARTUPOFF", "USBSTARTUPON;command", "USBSTARTUPON C:\\foreign.exe", "IPADPAIR", "IPADDELETEPAIR", "IPADAMDSDISABLED", "IPADDIAGNOSTICSHELL", "IPADCANDIDATE4", "IPADCANDIDATE99", "IPADCANDIDATEPAIR"} {
		if validMeasurement(kind, 0, id) == nil {
			t.Fatal("unexpected action admitted", kind)
		}
	}
}

func TestTemporaryBaselineBounds(t *testing.T) {
	id := strings.Repeat("c", 32)
	for _, kind := range []string{"UIBASELINE", "GUARDBASELINE"} {
		for _, n := range []int{0, 119, 120, 121} {
			if (validMeasurement(kind, n, id) == nil) != (n == 120) {
				t.Fatal(kind, n)
			}
		}
	}
	for _, kind := range []string{"UIDEFAULT", "GUARDDEFAULT"} {
		if validMeasurement(kind, 0, id) != nil || validMeasurement(kind, 1, id) == nil {
			t.Fatal(kind)
		}
	}
}

func TestSoftwareReconnectProfilesAreFixedAndCannotSelectDeviceOrDuration(t *testing.T) {
	nonce := strings.Repeat("0", 32)
	for _, kind := range []string{"IPADSOFTRECONNECT", "IPADSOFTRECONNECTON", "IPADSOFTRECONNECTOFF", "IPADSOFTRECONNECTCANCEL", "IPADSOFTRECONNECTSTATE"} {
		if err := validMeasurement(kind, 0, nonce); err != nil {
			t.Fatal(kind, err)
		}
		for _, seconds := range []int{-1, 1, 5, 120} {
			if validMeasurement(kind, seconds, nonce) == nil {
				t.Fatal("caller-selected duration accepted", kind, seconds)
			}
		}
	}
	for _, kind := range []string{"IPADSOFTRECONNECT USB\\VID_05AC&PID_12AB", "IPADSOFTRECONNECTDISABLED", "IPADSOFTRECONNECTSHELL", "IPADSOFTRECONNECTON;command", "IPADSOFTRECONNECTPAIR", "IPADSOFTRECONNECTDELETEPAIR"} {
		if validMeasurement(kind, 0, nonce) == nil {
			t.Fatal("arbitrary action/target accepted", kind)
		}
	}
}
