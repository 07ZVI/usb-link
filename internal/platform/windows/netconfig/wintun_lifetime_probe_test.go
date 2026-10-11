package netconfig

import (
	"encoding/json"
	"strings"
	"suhang/usbnet/internal/transport/wintun"
	"testing"
)

func TestWintunProbeAbsenceRequiresEveryCompletedRead(t *testing.T) {
	base := WintunLifetimeProbeRead{Complete: true}
	if !base.absent() {
		t.Fatal("complete absence rejected")
	}
	for _, mutate := range []func(*WintunLifetimeProbeRead){func(v *WintunLifetimeProbeRead) { v.Complete = false }, func(v *WintunLifetimeProbeRead) { v.MIBMatches = 1 }, func(v *WintunLifetimeProbeRead) { v.InstalledMatches = 1 }, func(v *WintunLifetimeProbeRead) { v.ExactInstanceMatches = 1 }, func(v *WintunLifetimeProbeRead) { v.IPv4Matches = 1 }} {
		v := base
		mutate(&v)
		if v.absent() {
			t.Fatal("unknown/present/ghost was called absent")
		}
	}
}

func TestWintunProbeActualNodeCannotAcceptProductionOrForeignDevice(t *testing.T) {
	n := nativeHostNode{Instance: "SWD\\WINTUN\\" + wintun.LifecycleProbeGUID, CMInstance: "SWD\\WINTUN\\" + wintun.LifecycleProbeGUID, DevInst: 1, SetupClass: hostNetClass, CMClass: hostNetClass, ClassType: 13, ClassSize: 16, Service: "Wintun", ServiceType: 18, ServiceSize: 14, SetupDriver: hostNetClass + `\0001`, CMDriver: hostNetClass + `\0001`, DriverType: 18, DriverSize: 88, SetupNetGUID: wintun.LifecycleProbeGUID, CMNetGUID: wintun.LifecycleProbeGUID, StateReadable: true}
	if !validLifecycleProbeNode(n) {
		t.Fatal("complete typed fixture rejected")
	}
	for name, change := range map[string]func(*nativeHostNode){
		"productionMac": func(v *nativeHostNode) {
			v.SetupNetGUID = "{A4611646-E050-4D25-B83E-633A5598F302}"
			v.CMNetGUID = "{A4611646-E050-4D25-B83E-633A5598F302}"
		},
		"class": func(v *nativeHostNode) { v.CMClass = "other" }, "service": func(v *nativeHostNode) { v.Service = "other" },
		"classType": func(v *nativeHostNode) { v.ClassType = 18 }, "classSize": func(v *nativeHostNode) { v.ClassSize = 15 },
		"serviceType": func(v *nativeHostNode) { v.ServiceType = 0 }, "serviceSize": func(v *nativeHostNode) { v.ServiceSize = 12 },
		"driver": func(v *nativeHostNode) { v.CMDriver = "other" }, "driverType": func(v *nativeHostNode) { v.DriverType = 0 }, "driverSize": func(v *nativeHostNode) { v.DriverSize = 0 },
		"setupDriver": func(v *nativeHostNode) { v.SetupDriver = "bad" }, "instance": func(v *nativeHostNode) { v.CMInstance = "other" },
		"wildcard": func(v *nativeHostNode) { v.Instance = "*"; v.CMInstance = "*" }, "devInst": func(v *nativeHostNode) { v.DevInst = 0 },
		"phantom": func(v *nativeHostNode) { v.StateReadable = false; v.StateError = 13 }, "disabled": func(v *nativeHostNode) { v.Problem = 22 },
		"unknown": func(v *nativeHostNode) { v.StateError = 1 }, "cmBinding": func(v *nativeHostNode) { v.CMNetGUID = "{A4611646-E050-4D25-B83E-633A5598F302}" },
	} {
		t.Run(name, func(t *testing.T) {
			v := n
			change(&v)
			if validLifecycleProbeNode(v) {
				t.Fatal("foreign/unknown fixture accepted")
			}
		})
	}
}

func TestWintunProbeReportContainsNoPrivateIdentityOrReadyClaim(t *testing.T) {
	b, e := json.Marshal(WintunLifetimeProbeReport{Schema: 1, ObservationOnly: true, ProcessID: 1, ProcessCreation: 2, Rounds: []WintunLifetimeProbeRound{{Round: 1}}})
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"instance", "dll_path", "guid", "address", "ready", "verified_owner"} {
		if strings.Contains(string(b), `"`+key+`"`) {
			t.Fatalf("private/admission field: %s", key)
		}
	}
}

func TestWintunProbeReportBindsActualChildAndFiveCompletedRounds(t *testing.T) {
	v := WintunLifetimeProbeReport{Schema: 1, ObservationOnly: true, HoldModule: true, ProcessID: 51, ProcessCreation: 72, PinnedModules: 1, Stage: "complete"}
	for i := 1; i <= 5; i++ {
		v.Rounds = append(v.Rounds, WintunLifetimeProbeRound{Round: i, CreateCalled: true, CreateReturned: true, CreatorVerified: true, CloseReturned: true, Before: WintunLifetimeProbeRead{Complete: true}, After: WintunLifetimeProbeRead{Complete: true}})
	}
	if e := ValidateWintunLifetimeProbeReport(v, true, 51, 72); e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*WintunLifetimeProbeReport){
		"failedTransport": func(v *WintunLifetimeProbeReport) {
			v.TransportError = "WINTUN_PROBE_CHILD_CREATION_CHANGED_AFTER_WAIT"
		},
		"forgedPID":             func(v *WintunLifetimeProbeReport) { v.ProcessID++ },
		"reusedPID":             func(v *WintunLifetimeProbeReport) { v.ProcessCreation++ },
		"wrongMode":             func(v *WintunLifetimeProbeReport) { v.HoldModule = false },
		"noObservationBoundary": func(v *WintunLifetimeProbeReport) { v.ObservationOnly = false },
		"shortRun":              func(v *WintunLifetimeProbeReport) { v.Rounds = v.Rounds[:4] },
		"repeatRound":           func(v *WintunLifetimeProbeReport) { v.Rounds[1].Round = 1 },
		"notClosed":             func(v *WintunLifetimeProbeReport) { v.Rounds[1].CloseReturned = false },
		"unknownRead":           func(v *WintunLifetimeProbeReport) { v.Rounds[1].After.Complete = false },
		"MIBGhost":              func(v *WintunLifetimeProbeReport) { v.Rounds[1].After.MIBMatches = 1 },
		"phantom":               func(v *WintunLifetimeProbeReport) { v.Rounds[1].After.InstalledMatches = 1 },
		"missingPIN":            func(v *WintunLifetimeProbeReport) { v.PinnedModules = 0 },
		"privateError":          func(v *WintunLifetimeProbeReport) { v.Code = `C:\\private\\path` },
		"absentNativeCall":      func(v *WintunLifetimeProbeReport) { v.Rounds[1].CreateCalled = false },
		"impossibleDuration":    func(v *WintunLifetimeProbeReport) { v.Rounds[1].CloseSettleMS = 120001 },
	} {
		t.Run(name, func(t *testing.T) {
			c := v
			c.Rounds = append([]WintunLifetimeProbeRound(nil), v.Rounds...)
			change(&c)
			if ValidateWintunLifetimeProbeReport(c, true, 51, 72) == nil {
				t.Fatal("invalid observation accepted")
			}
		})
	}
	// A bounded failure is useful evidence but is never reported as completed.
	v.Stage = "closing"
	v.Code = "WINTUN_PROBE_CLOSE_ABSENCE_UNCONFIRMED"
	v.Rounds = v.Rounds[:1]
	v.Rounds[0].After.MIBMatches = 1
	if e := ValidateWintunLifetimeProbeReport(v, true, 51, 72); e != nil {
		t.Fatal(e)
	}
}
