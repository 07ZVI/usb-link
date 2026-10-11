//go:build windows && amd64

package netconfig

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"suhang/usbnet/internal/transport/usbaddress"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	macMTUIPHelper       = windows.NewLazySystemDLL("iphlpapi.dll")
	macMTUGuidToLuid     = macMTUIPHelper.NewProc("ConvertInterfaceGuidToLuid")
	macMTUSetIPInterface = macMTUIPHelper.NewProc("SetIpInterfaceEntry")
)

// SetVerifiedMacMTUNative is called only after the existing nonce-verified
// jumbo trial. Initial bridge setup still establishes MTU 1500. This operation
// changes IPv4 NlMtu only, plus the API-required zero SitePrefixLength; it never
// creates an address, route, firewall permission or network profile.
func SetVerifiedMacMTUNative(ctx context.Context, index uint32, guid string, luid uint64, mtu int) error {
	if ctx == nil {
		return errors.New("USB_MAC_MTU_CONTEXT_REQUIRED")
	}
	if err := validateVerifiedMacMTUScope(index, guid, luid, mtu); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	release, err := usbaddress.ConfigurationLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	identity := func() error { return verifyNativeMacMTUIdentity(ctx, index, guid, luid) }
	if err := identity(); err != nil {
		return err
	}
	before := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: luid}
	if err := windows.GetIpInterfaceEntry(&before); err != nil {
		return fmt.Errorf("USB_MAC_MTU_READ_FAILED: %w", err)
	}
	row, err := prepareVerifiedMacMTURow(before, index, luid, mtu)
	if err != nil {
		return err
	}
	if err := identity(); err != nil {
		return err
	}
	if before.NlMtu != uint32(mtu) {
		if err := macMTUSetIPInterface.Find(); err != nil {
			return fmt.Errorf("USB_MAC_MTU_API_UNAVAILABLE: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		code, _, _ := macMTUSetIPInterface.Call(uintptr(unsafe.Pointer(&row)))
		runtime.KeepAlive(row)
		if code != 0 {
			return fmt.Errorf("USB_MAC_MTU_SET_%d", code)
		}
	}
	if err := identity(); err != nil {
		return err
	}
	after := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: luid}
	if err := windows.GetIpInterfaceEntry(&after); err != nil {
		return fmt.Errorf("USB_MAC_MTU_READBACK_FAILED: %w", err)
	}
	if after.Family != windows.AF_INET || after.InterfaceIndex != index || after.InterfaceLuid != luid || after.NlMtu != uint32(mtu) {
		return errors.New("USB_MAC_MTU_READBACK_CHANGED")
	}
	// Interface policy outside MTU must still match the original snapshot.
	if after.ForwardingEnabled != before.ForwardingEnabled || after.WeakHostSend != before.WeakHostSend || after.WeakHostReceive != before.WeakHostReceive || after.UseAutomaticMetric != before.UseAutomaticMetric || after.Metric != before.Metric || after.DisableDefaultRoutes != before.DisableDefaultRoutes {
		return errors.New("USB_MAC_MTU_POLICY_CHANGED")
	}
	return identity()
}

func prepareVerifiedMacMTURow(before windows.MibIpInterfaceRow, index uint32, luid uint64, mtu int) (windows.MibIpInterfaceRow, error) {
	if index == 0 || luid == 0 || before.Family != windows.AF_INET || before.InterfaceIndex != index || before.InterfaceLuid != luid || (mtu != 1500 && mtu != 9000 && mtu != 16000) {
		return windows.MibIpInterfaceRow{}, errors.New("USB_MAC_MTU_ROW_CHANGED")
	}
	row := before
	row.SitePrefixLength = 0
	row.NlMtu = uint32(mtu)
	return row, nil
}

func verifyNativeMacMTUIdentity(ctx context.Context, index uint32, guid string, luid uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	parsed, err := windows.GUIDFromString(guid)
	if err != nil {
		return errors.New("USB_MAC_MTU_GUID_INVALID")
	}
	if err := macMTUGuidToLuid.Find(); err != nil {
		return fmt.Errorf("USB_MAC_MTU_API_UNAVAILABLE: %w", err)
	}
	var mapped uint64
	code, _, _ := macMTUGuidToLuid.Call(uintptr(unsafe.Pointer(&parsed)), uintptr(unsafe.Pointer(&mapped)))
	runtime.KeepAlive(parsed)
	if code != 0 || mapped != luid {
		return errors.New("USB_MAC_MTU_GUID_LUID_CHANGED")
	}
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfEntryNormal, &table); err != nil {
		return fmt.Errorf("USB_MAC_MTU_TABLE_UNAVAILABLE: %w", err)
	}
	if table == nil {
		return errors.New("USB_MAC_MTU_TABLE_INVALID")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 65536 {
		return errors.New("USB_MAC_MTU_TABLE_INVALID")
	}
	rows := make([]macMTUIdentity, 0, int(table.NumEntries))
	for _, row := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
		rows = append(rows, macMTUIdentity{Index: row.InterfaceIndex, LUID: row.InterfaceLuid, GUID: row.InterfaceGuid.String(), Alias: windows.UTF16ToString(row.Alias[:]), Type: row.Type})
	}
	if err := validateVerifiedMacMTUIdentity(rows, index, guid, luid); err != nil {
		return err
	}
	return ctx.Err()
}
