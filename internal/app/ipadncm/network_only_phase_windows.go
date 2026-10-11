//go:build windows && amd64

package ipadncm

import (
	"context"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

type networkOnlyPhaseInventory struct {
	Nodes []portableNodeReceipt
	Error error
}

func networkOnlyPhaseName(phase string) string {
	switch phase {
	case "before_driver", "after_driver", "after_mode":
		return phase
	default:
		return "unspecified_ensure"
	}
}

// No writes, service control, consent, or polling. The budget is checked
// between native calls; a synchronous Windows call itself cannot be preempted.
func observeNetworkOnlyPhase(ctx context.Context, expected Snapshot, phase, point, outcome string, used *networkOnlyPhaseInventory) {
	if !NetworkOnlyEnabled() || !phaseCapture.active(time.Now()) {
		return
	}
	started := time.Now()
	d := NetworkOnlyPhaseDiagnostic{ObservedUTC: started.UTC().Format(time.RFC3339Nano), Phase: networkOnlyPhaseName(phase), Point: point, Outcome: outcome}
	if used != nil {
		d.InventoryFromEnsure = true
		d.setPresentInventory(len(used.Nodes), used.Error == nil)
		if used.Error != nil {
			d.PresentError = "PRESENT_PORTABLE_ENUMERATION_UNREADABLE_OR_LIMIT"
		}
	}
	monitorDiagnostics.Lock()
	if monitorDiagnostics.deviceKind == "iPad" && !monitorDiagnostics.attemptStarted.IsZero() {
		d.Attempt = monitorDiagnostics.attempt
		d.ElapsedMS = time.Since(monitorDiagnostics.attemptStarted).Milliseconds()
	}
	monitorDiagnostics.Unlock()
	budget, capture := phaseCapture.begin(d.Attempt, started)
	if !capture {
		return
	}
	defer func() {
		elapsed := time.Since(started)
		d.ObservationMS = elapsed.Milliseconds()
		phaseCapture.finish(elapsed)
		networkOnlyPhases.record(d)
	}()
	withinBudget := func() bool {
		return ctx != nil && ctx.Err() == nil && time.Since(started) < budget && phaseCapture.active(time.Now())
	}
	budgetEnded := func() {
		d.ObservationError, d.AllError = "OBSERVATION_BUDGET_ENDED", "OBSERVATION_BUDGET_ENDED"
		if !d.PresentComplete && d.PresentError == "" {
			d.PresentError = "PRESENT_INVENTORY_NOT_OBSERVED_BUDGET_ENDED"
		}
	}
	if !withinBudget() {
		d.PresentError, d.AllError = "OBSERVATION_CONTEXT_UNAVAILABLE", "OBSERVATION_CONTEXT_UNAVAILABLE"
		return
	}
	fresh := Inspect()
	if !withinBudget() {
		budgetEnded()
		return
	}
	d.DescriptorBound = networkOnlyUSBEligible(expected) && networkOnlyUSBEligible(fresh) && descriptorAttachment(expected).same(descriptorAttachment(fresh))
	if !d.DescriptorBound {
		d.PresentError, d.AllError = "CURRENT_TARGET_CHANGED_OR_UNPROVEN", "CURRENT_TARGET_CHANGED_OR_UNPROVEN"
		return
	}
	root := exactIPadRoot(fresh)
	dev := fresh.Devices[0]
	d.Configuration = dev.CurrentConfiguration
	for _, cfg := range dev.Configurations {
		if cfg.Value == dev.CurrentConfiguration {
			for _, iface := range cfg.Interfaces {
				if iface.Class == 6 && iface.Subclass == 1 && iface.Protocol == 1 {
					d.PTPDescriptor = true
				}
			}
		}
	}
	if m, e := mgr.Connect(); e == nil {
		defer m.Disconnect()
		if !withinBudget() {
			budgetEnded()
			return
		}
		if service, e := m.OpenService("Apple Mobile Device Service"); e == nil {
			defer service.Close()
			if !withinBudget() {
				budgetEnded()
				return
			}
			state, se := service.Query()
			if !withinBudget() {
				budgetEnded()
				return
			}
			config, ce := service.Config()
			if se == nil && ce == nil {
				d.ServiceReadable, d.ServiceState, d.ServiceStartType = true, uint32(state.State), config.StartType
			}
		}
	}
	if !withinBudget() {
		budgetEnded()
		return
	}
	var present []portableNodeReceipt
	if used != nil {
		present = used.Nodes
	} else {
		var err error
		present, err = portableNodes(root) // All-enumerator PRESENT WPD/Image set.
		d.setPresentInventory(len(present), err == nil)
		if err != nil {
			d.PresentError = "PRESENT_PORTABLE_ENUMERATION_UNREADABLE_OR_LIMIT"
		}
	}
	if !withinBudget() {
		budgetEnded()
		return
	}
	networkOnly.Lock()
	dir := networkOnly.dir
	networkOnly.Unlock()
	receipt, receiptErr := readNetworkOnlyReceipt(dir)
	if !withinBudget() {
		budgetEnded()
		return
	}
	d.ReceiptValid = receiptErr == nil
	var owned []portableNodeReceipt
	if receiptErr != nil {
		d.OwnedError = "OWNED_RECEIPT_ABSENT_OR_UNREADABLE"
	} else {
		for _, node := range receipt.Nodes {
			if !validPortableReceipt(node) || !strings.EqualFold(node.Root, root) {
				d.OwnedError = "OWNED_RECEIPT_CURRENT_ROOT_UNPROVEN"
				owned = nil
				break
			}
			owned = append(owned, node)
		}
		if d.OwnedError == "" {
			n := len(owned)
			d.OwnedCount = &n
		}
	}
	// These two collections remain separately labelled even for the same ID.
	d.PresentOmitted, d.OwnedOmitted = max(0, len(present)-16), max(0, len(owned)-16)
	present, owned = present[:min(16, len(present))], owned[:min(16, len(owned))]
	for _, n := range present {
		d.PresentNodes = append(d.PresentNodes, NetworkOnlyPhaseNode{Digest: portableNodeDigest(n), Class: n.Class, Native: PortableNodeObservation{Error: "EXACT_ALL_INSTANCE_NOT_FOUND"}})
	}
	for _, n := range owned {
		d.OwnedNodes = append(d.OwnedNodes, NetworkOnlyPhaseNode{Digest: portableNodeDigest(n), Class: n.Class, Native: PortableNodeObservation{Error: "EXACT_ALL_INSTANCE_NOT_FOUND"}})
	}
	if !withinBudget() {
		budgetEnded()
		return
	}
	set, err := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES, 0, "")
	if err != nil {
		d.AllError = "ALL_INSTANCE_SET_UNAVAILABLE"
		return
	}
	defer set.Close()
	for i := 0; i < 4096; i++ {
		if !withinBudget() {
			budgetEnded()
			return
		}
		info, err := set.EnumDeviceInfo(i)
		if err == windows.ERROR_NO_MORE_ITEMS {
			d.AllComplete = true
			return
		}
		if err != nil {
			d.AllError = "ALL_INSTANCE_ENUMERATION_UNREADABLE"
			return
		}
		if !withinBudget() {
			budgetEnded()
			return
		}
		id, err := set.DeviceInstanceID(info)
		if err != nil {
			d.AllError = "ALL_INSTANCE_ID_UNREADABLE"
			return
		}
		if !withinBudget() {
			budgetEnded()
			return
		}
		if strings.EqualFold(id, root) {
			d.RootMatches++
			if d.RootMatches == 1 {
				var class windows.GUID
				var typ windows.DEVPROPTYPE
				size := uint32(16)
				d.RootClassCR = softwareProperty(info.DevInst, 10, &typ, unsafe.Pointer(&class), &size)
				d.RootClassType, d.RootClassSize = uint32(typ), size
				d.RootSetupClassGUID = info.ClassGUID.String()
				if d.RootClassCR == 0 && typ == windows.DEVPROP_TYPE_GUID && size == 16 {
					d.RootCMClassGUID = class.String()
				}
			}
		}
		if !withinBudget() {
			budgetEnded()
			return
		}
		observe := func(nodes []portableNodeReceipt, rows []NetworkOnlyPhaseNode) bool {
			for j, n := range nodes {
				if strings.EqualFold(n.ID, id) {
					if !withinBudget() {
						return false
					}
					rows[j].Matches++
					if rows[j].Matches == 1 {
						rows[j].Native = portableNativeObservation(info.DevInst, n)
					} else {
						rows[j].Native = PortableNodeObservation{Error: "DUPLICATE_EXACT_ALL_INSTANCE"}
					}
				}
			}
			return withinBudget()
		}
		if !observe(present, d.PresentNodes) || !observe(owned, d.OwnedNodes) {
			budgetEnded()
			return
		}
	}
	d.AllError = "ALL_INSTANCE_ENUMERATION_LIMIT"
}
