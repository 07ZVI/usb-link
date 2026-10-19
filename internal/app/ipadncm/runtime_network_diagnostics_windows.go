//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func collectRuntimeNetworkDiagnostics(ctx context.Context) RuntimeNetworkDiagnostic {
	r := RuntimeNetworkDiagnostic{Status: "PNP_NOT_READ", TCP: RuntimeNetworkTCP{Status: "NOT_READ"}}
	// PnP only: no hub handles, descriptors, Apple pairing, mode requests or writes.
	snapshot := inventoryPnP(ctx)
	if snapshot.Error != "" {
		r.Status = "PNP_READ_FAILED"
		return r
	}
	ids := make([]string, 0, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		ids = append(ids, node.instanceID)
	}
	presence := idlePresenceFromIDs(ids, true)
	var root Node
	if presence.candidate {
		for _, node := range snapshot.Nodes {
			if strings.EqualFold(node.IDPrefix, `USB\VID_05AC&PID_12AB`) {
				root = node
				break
			}
		}
		r.Status = "ROOT_SCOPED"
	} else if presence.absent {
		r.Status = "ROOT_ABSENT"
	} else {
		r.Status = "ROOT_UNCONFIRMED_OR_AMBIGUOUS"
	}
	var addresses []string
	if root.instanceID != "" {
		for _, node := range snapshot.Nodes {
			if ctx.Err() != nil {
				r.Status = "BUDGET_EXCEEDED"
				return r
			}
			if !strings.EqualFold(node.Service, "UsbNcm") {
				continue
			}
			belongs, err := descendantOfPortableRoot(node.devInst, root.instanceID)
			if err != nil {
				r.Status = "ANCESTRY_READ_FAILED"
				continue
			}
			if !belongs {
				continue
			}
			if len(r.Adapters) >= runtimeNetworkAdapterLimit {
				r.AdaptersOmitted++
				continue
			}
			entry := RuntimeNetworkAdapter{}
			mapped := readNCMAdapters(Snapshot{Nodes: []Node{node}})
			if len(mapped) != 1 {
				entry.Error = "NCM_NOT_STARTED_OR_STATE_UNREADABLE"
				r.Adapters = append(r.Adapters, entry)
				continue
			}
			a := mapped[0]
			entry.Index, entry.OperStatus, entry.Error = a.InterfaceIndex, a.OperStatus, a.Error
			entry.AdminStatus, entry.MediaState = a.AdminStatus, a.MediaConnectState
			entry.StatusFlags, entry.StatusRead = a.InterfaceAndOperStatusFlags, a.StatisticsRead
			// Recheck ancestry after the separate adapter query; PnP can change mid-read.
			belongs, err = descendantOfPortableRoot(node.devInst, root.instanceID)
			if err != nil || !belongs || !runtimeNetworkRootPresent(root) {
				r.Status = "ROOT_CHANGED_DURING_READ"
				r.Adapters = nil
				return r
			}
			for _, value := range a.Addresses {
				ip, err := netip.ParseAddr(value.IP)
				if err != nil || !ip.Is4() || value.PrefixLength > 32 {
					continue
				}
				address := netip.PrefixFrom(ip, int(value.PrefixLength)).String()
				if len(entry.IPv4) < runtimeNetworkAddressLimit {
					entry.IPv4 = append(entry.IPv4, address)
				} else {
					entry.AddressesOmitted++
				}
				if a.Matched && a.Error == "" {
					addresses = append(addresses, address)
				}
			}
			r.Adapters = append(r.Adapters, entry)
		}
	}
	if ctx.Err() != nil {
		r.Status = "BUDGET_EXCEEDED"
		return r
	}
	table, status := runtimeNetworkTCPTable(ctx)
	if status != "" {
		r.TCP.Status = status
		return r
	}
	r.TCP = runtimeNetworkTCP(table, runtimeNetworkPairs(addresses))
	return r
}

func runtimeNetworkRootPresent(root Node) bool {
	var id [1024]uint16
	cr, _, _ := portableID.Call(uintptr(root.devInst), uintptr(unsafe.Pointer(&id[0])), uintptr(len(id)), 0)
	if cr != 0 || !strings.EqualFold(windows.UTF16ToString(id[:]), root.instanceID) {
		return false
	}
	var status, problem uint32
	return windows.CM_Get_DevNode_Status(&status, &problem, root.devInst, 0) == nil
}

func runtimeNetworkTCPTable(ctx context.Context) ([]byte, string) {
	p := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
	if p.Find() != nil {
		return nil, "API_UNAVAILABLE"
	}
	var size uint32
	rc, _, _ := p.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 5, 0)
	if rc != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, "SIZE_QUERY_FAILED"
	}
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return nil, "BUDGET_EXCEEDED"
		}
		if size < 4 || size > 1<<20 {
			return nil, "BUFFER_LIMIT"
		}
		buffer := make([]byte, size)
		rc, _, _ = p.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 5, 0)
		if rc == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if rc != 0 {
			return nil, fmt.Sprintf("READ_WIN32_%d", rc)
		}
		if size > uint32(len(buffer)) {
			return nil, "TABLE_INVALID"
		}
		return buffer[:size], ""
	}
	return nil, "TABLE_CHANGED_TOO_OFTEN"
}
