//go:build windows && amd64

package interfaceconfig

import (
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

// ReadOwnedDADObservations reads the protected ledger and bounded native MIB
// tables. It never calls an owner callback, writes a file or interface, retires
// an obligation, opens a device, restores an original or produces Verified.
// A matching MIB row (including a ghost) is not proof of device ownership.
func ReadOwnedDADObservations(dir string) ([]OwnedDADObservation, error) {
	// Atomic file replacement gives a complete protected snapshot. No writer
	// lease is needed for observation, and status must not wait for mutations.
	ledger, found, e := readOwnedDADFile(dir)
	if e != nil {
		return nil, e
	}
	out := make([]OwnedDADObservation, 0, len(ledger.Originals))
	if !found || len(ledger.Originals) == 0 {
		return out, nil
	}
	var table *windows.MibIfTable2
	readError := ""
	if windows.GetIfTable2Ex(windows.MibIfEntryNormal, &table) != nil || table == nil {
		readError = "NATIVE_MAPPING_UNREADABLE"
	} else {
		defer windows.FreeMibTable(unsafe.Pointer(table))
		if table.NumEntries > 65536 {
			readError = "NATIVE_MAPPING_UNBOUNDED"
		}
	}
	for _, original := range ledger.Originals {
		observation := ownedDADObservation(original)
		if readError != "" {
			observation.Code = readError
			out = append(out, observation)
			continue
		}
		var selected windows.MibIfRow2
		count := 0
		for _, r := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
			if r.InterfaceLuid == original.Identity.Scope.LUID || strings.EqualFold(r.InterfaceGuid.String(), original.Identity.Scope.GUID) {
				count++
				selected = r
			}
		}
		switch {
		case count == 0:
			observation.Code = "NATIVE_MAPPING_ABSENT_NOT_FULL_ABSENCE_PROOF"
		case count != 1:
			observation.Code = "NATIVE_MAPPING_AMBIGUOUS"
		case selected.InterfaceIndex == 0 || selected.InterfaceLuid == 0 || !strings.EqualFold(selected.InterfaceGuid.String(), observation.GUID):
			observation.Code = "NATIVE_MAPPING_CONFLICT"
		default:
			index, luid := selected.InterfaceIndex, selected.InterfaceLuid
			observation.CurrentIndex = &index
			observation.CurrentLUID = &luid
			r := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: luid}
			if windows.GetIpInterfaceEntry(&r) != nil || r.InterfaceIndex != index || r.InterfaceLuid != luid {
				observation.Code = "NATIVE_DAD_UNREADABLE"
				break
			}
			// Read the current interface once more after the IP value query. If the
			// mapping changed, export no Dad value from that unstable observation.
			fresh := windows.MibIfRow2{InterfaceLuid: luid}
			if windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &fresh) != nil || fresh.InterfaceIndex != index || fresh.InterfaceLuid != luid || fresh.InterfaceGuid != selected.InterfaceGuid {
				observation.Code = "NATIVE_MAPPING_CHANGED_DURING_READ"
				break
			}
			value := r.DadTransmits
			observation.CurrentDadTransmits = &value
			observation.Code = "READ_ONLY_MAPPING_NOT_OWNERSHIP"
			if luid != observation.LUID {
				observation.Code = "LUID_CHANGED_READ_ONLY_NOT_OWNERSHIP"
			}
		}
		out = append(out, observation)
	}
	return out, nil
}
