package ipadncm

import (
	"sync"
	"testing"
)

func TestIndependentDeviceSessionsAndSelection(t *testing.T) {
	mac := &applicationState{r: ApplicationResult{DeviceKind: "Mac", WindowsIPv4: "10.6.9.1"}}
	ipad := &applicationState{r: ApplicationResult{DeviceKind: "iPad", WindowsIPv4: "10.6.10.1"}}
	displaySessions.Lock()
	displaySessions.states = map[string]*applicationState{"Mac": mac, "iPad": ipad}
	displaySessions.selected, displaySessions.manual = "Mac", false
	displaySessions.Unlock()
	defer func() {
		displaySessions.Lock()
		displaySessions.states = nil
		displaySessions.selected = ""
		displaySessions.manual = false
		displaySessions.Unlock()
	}()
	facade := &applicationState{selected: selectedDeviceMonitor}
	ipad.update(func(r *ApplicationResult) { r.Status = "USB_APPLICATION_TRIAL_RUNNING" })
	if facade.snapshot().DeviceKind != "iPad" {
		t.Fatal("active device not automatically selected")
	}
	if !selectDevice("Mac") || selectDevice("unknown") {
		t.Fatal("invalid selection")
	}
	var wg sync.WaitGroup
	for _, s := range []*applicationState{mac, ipad} {
		wg.Add(1)
		go func(s *applicationState) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				s.update(func(r *ApplicationResult) { r.MacDHCPACKs++ })
				_ = facade.snapshot()
				_ = deviceSummary()
			}
		}(s)
	}
	wg.Wait()
	if mac.snapshot().MacDHCPACKs != 500 || ipad.snapshot().MacDHCPACKs != 500 {
		t.Fatal("sessions overwrite each other")
	}
	mac.update(func(r *ApplicationResult) { r.Status = "MAC_RUNNING" })
	ipad.update(func(r *ApplicationResult) { r.Status = "MONITOR_WAITING" })
	if facade.snapshot().Status != "MAC_RUNNING" || facade.snapshot().WindowsIPv4 != "10.6.9.1" {
		t.Fatal("iPad disconnect changed Mac")
	}
}

func TestDualUSBPresenceIsRoutedIndependently(t *testing.T) {
	ids := []string{`USB\VID_05AC&PID_1903\MAC`, `USB\VID_05AC&PID_12AB\IPAD`, `USB\VID_05AC&PID_1903&MI_00\CHILD`}
	m, mp := idleUSBPresenceFromIDs(onlyMacIDs(ids), true)
	i, ip := idleUSBPresenceFromIDs(onlyIPadIDs(ids), true)
	if m != "Mac" || i != "iPad" || !mp.candidate || !ip.candidate {
		t.Fatal("dual roots blocked one another")
	}
	_, unknown := idleUSBPresenceFromIDs(onlyMacIDs(ids), false)
	if unknown.absent || unknown.readable {
		t.Fatal("failed enumeration treated as detach")
	}
	_, absent := idleUSBPresenceFromIDs(onlyMacIDs(ids[1:2]), true)
	if !absent.absent {
		t.Fatal("Mac absence not recognized while iPad stays attached")
	}
}
