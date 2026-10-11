//go:build windows && amd64

package ipadncm

import (
	"fmt"
	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/transport/ipadsession"
	"unsafe"
)

func readUSBHostFlags(luid uint64) (*ipadsession.HostFlags, error) {
	r := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: luid}
	if e := windows.GetIpInterfaceEntry(&r); e != nil {
		return nil, e
	}
	return &ipadsession.HostFlags{Send: r.WeakHostSend != 0, Receive: r.WeakHostReceive != 0, Forward: r.ForwardingEnabled != 0}, nil
}
func setUSBHostFlags(p ipadsession.Plan, restore bool) string {
	if p.Version != 5 && p.Version != 6 {
		return ""
	}
	if e := verifyApplicationLUID(p); e == "ADAPTER_ABSENT" && restore {
		return ""
	} else if e != "" {
		return e
	}
	r := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
	if err := windows.GetIpInterfaceEntry(&r); err != nil {
		// The adapter can still exist in NDIS after reboot/re-enumeration while
		// its old IPv4 interface has disappeared. Prove that exact family absent
		// instead of trying to restore fields on an object that no longer exists.
		if restore && (err == windows.ERROR_NOT_FOUND || err == windows.ERROR_FILE_NOT_FOUND) {
			if absent, e := ipv4InterfaceAbsent(p); e == nil && absent {
				return ""
			}
		}
		return fmt.Sprintf("APPLICATION_HOST_FLAGS_QUERY_FAILED: %v", err)
	}
	if r.InterfaceIndex != p.Index {
		return "APPLICATION_HOST_FLAGS_INDEX_CHANGED"
	}
	send, receive, forward := uint8(1), uint8(1), uint8(1)
	if restore {
		forward = 0
		if p.HostFlags.Forward {
			forward = 1
		}
		send = 0
		receive = 0
		if p.HostFlags.Send {
			send = 1
		}
		if p.HostFlags.Receive {
			receive = 1
		}
		if (r.WeakHostSend != 1 && r.WeakHostSend != send) || (r.WeakHostReceive != 1 && r.WeakHostReceive != receive) || (r.ForwardingEnabled != 1 && r.ForwardingEnabled != forward) {
			return "APPLICATION_HOST_FLAGS_OWNERSHIP_CHANGED"
		}
	}
	r.ForwardingEnabled = forward
	r.SitePrefixLength = 0
	r.WeakHostSend = send
	r.WeakHostReceive = receive
	rc, _, _ := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SetIpInterfaceEntry").Call(uintptr(unsafe.Pointer(&r)))
	if rc != 0 {
		return fmt.Sprintf("APPLICATION_HOST_FLAGS_SET_%d", rc)
	}
	r = windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
	if windows.GetIpInterfaceEntry(&r) != nil || r.WeakHostSend != send || r.WeakHostReceive != receive || r.ForwardingEnabled != forward {
		return "APPLICATION_HOST_FLAGS_READBACK_FAILED"
	}
	return ""
}

func ipv4InterfaceAbsent(p ipadsession.Plan) (bool, error) {
	if e := verifyApplicationLUID(p); e != "" {
		return false, fmt.Errorf("%s", e)
	}
	var table *windows.MibIpInterfaceTable
	if e := windows.GetIpInterfaceTable(windows.AF_INET, &table); e != nil {
		return false, e
	}
	if table == nil {
		return false, fmt.Errorf("nil IPv4 table")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 65536 {
		return false, fmt.Errorf("invalid IPv4 table")
	}
	for _, r := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
		if r.InterfaceLuid == p.LUID || r.InterfaceIndex == p.Index {
			return false, nil
		}
	}
	if e := verifyApplicationLUID(p); e != "" {
		return false, fmt.Errorf("%s", e)
	}
	return true, nil
}
func restoreUSBHostFlags(p ipadsession.Plan) string { return setUSBHostFlags(p, true) }
