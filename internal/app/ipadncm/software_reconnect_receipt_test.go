package ipadncm

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func softwareJournalFixture() softwareReconnectJournal {
	t := draftTarget()
	return softwareReconnectJournal{Version: 1, StartedUTC: time.Now().UTC().Format(time.RFC3339Nano), RootID: t.RootID, HardwarePrefix: t.HardwarePrefix, Class: t.Class, Service: t.Service, Hub: `\\?\USB#ROOT_HUB30#4&abc&0&0#{f18a0e88-c30c-11d0-8815-00a0c906bed8}`, Port: 4, ParentID: `USB\ROOT_HUB30\4&abc&0&0`, LocationPaths: []string{"PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(4)"}, Configuration: 5, Product: "iPad", Status: t.Status, Problem: t.Problem, FlagsPresent: true}
}
func enabledSoftwareObservation(j softwareReconnectJournal) SoftwareReconnectNativeObservation {
	return SoftwareReconnectNativeObservation{ExactInstance: true, ExactClass: true, ExactService: true, ExactParent: true, HubParentMatches: true, ExactLocation: true, ExactPhysicalPort: true, UniqueRoot: true, StateReadable: true, FlagsReadable: true, FlagsPresent: j.FlagsPresent, Status: j.Status, Problem: j.Problem, ConfigFlags: j.ConfigFlags}
}
func TestSoftwareReceiptStrictDecodeAndOriginalPropertyPresence(t *testing.T) {
	j := softwareJournalFixture()
	b, _ := json.Marshal(j)
	got, e := decodeSoftwareReconnectJournal(b)
	if e != nil || !got.FlagsPresent || got.RootID != j.RootID {
		t.Fatal(got, e)
	}
	for _, bad := range []string{
		string(b) + " {}",
		strings.Replace(string(b), `,"original_config_flags_present":true`, ``, 1),
		strings.Replace(string(b), `"original_config_flags_present":true`, `"original_config_flags_present":null`, 1),
		strings.Replace(string(b), `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(string(b), `"version":1`, `"version":1,"command":"arbitrary"`, 1),
		strings.Repeat(" ", softwareReconnectReceiptLimit+1),
	} {
		if _, e := decodeSoftwareReconnectJournal([]byte(bad)); e == nil {
			t.Fatal("unsafe receipt accepted", bad[:min(len(bad), 120)])
		}
	}
	j.FlagsPresent = false
	j.ConfigFlags = 8
	if j.valid() {
		t.Fatal("absent original property with nonzero value accepted")
	}
	j.ConfigFlags = 0
	if !j.valid() {
		t.Fatal("absent zero original property rejected")
	}
}
func TestSoftwareRecoveryDoesNotEnableForeignOrUnprovenRoot(t *testing.T) {
	j := softwareJournalFixture()
	good := enabledSoftwareObservation(j)
	if !good.enabled(j) {
		t.Fatal("original enabled fixture rejected")
	}
	for name, change := range map[string]func(*SoftwareReconnectNativeObservation){
		"other instance":                         func(s *SoftwareReconnectNativeObservation) { s.ExactInstance = false },
		"hub class":                              func(s *SoftwareReconnectNativeObservation) { s.ExactClass = false },
		"changed driver":                         func(s *SoftwareReconnectNativeObservation) { s.ExactService = false },
		"parent belongs to another physical hub": func(s *SoftwareReconnectNativeObservation) { s.HubParentMatches = false },
		"different parent":                       func(s *SoftwareReconnectNativeObservation) { s.ExactParent = false },
		"another port":                           func(s *SoftwareReconnectNativeObservation) { s.ExactPhysicalPort = false },
		"another location":                       func(s *SoftwareReconnectNativeObservation) { s.ExactLocation = false },
		"two roots":                              func(s *SoftwareReconnectNativeObservation) { s.UniqueRoot = false },
		"unreadable state":                       func(s *SoftwareReconnectNativeObservation) { s.StateReadable = false },
		"unreadable flags":                       func(s *SoftwareReconnectNativeObservation) { s.FlagsReadable = false },
		"external persistent disable":            func(s *SoftwareReconnectNativeObservation) { s.ConfigFlags = 1 },
		"property removed":                       func(s *SoftwareReconnectNativeObservation) { s.FlagsPresent = false },
		"restart pending":                        func(s *SoftwareReconnectNativeObservation) { s.Status |= 0x100 },
		"removal pending":                        func(s *SoftwareReconnectNativeObservation) { s.Status |= 0x40000 },
	} {
		t.Run(name, func(t *testing.T) {
			s := good
			change(&s)
			if s.enabled(j) || s.disabled(j) || s.owned(j) {
				t.Fatal("foreign recovery target accepted", s)
			}
		})
	}
	disabled := good
	disabled.Status &^= 8
	disabled.Status |= 0x400
	disabled.Problem = 22
	if !disabled.disabled(j) || disabled.enabled(j) {
		t.Fatal("quiet disabled state not distinguished", disabled)
	}
	for _, problem := range []uint32{0, 10, 14, 24, 28, 32} {
		s := disabled
		s.Problem = problem
		if s.disabled(j) {
			t.Fatal("unowned CM problem accepted", problem)
		}
	}
	s := disabled
	s.Status |= 8
	if s.disabled(j) {
		t.Fatal("CR success without actual disabled readback accepted")
	}
}
