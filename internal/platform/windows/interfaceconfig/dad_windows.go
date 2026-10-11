//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var configMu sync.Mutex
var dadEnabled atomic.Bool
var persistentEnabled atomic.Bool

func DADZeroEnabled() bool        { return dadEnabled.Load() }
func SetDADZeroEnabled(v bool)    { dadEnabled.Store(v) }
func SetPersistentEnabled(v bool) { persistentEnabled.Store(v) }

var setInterface = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SetIpInterfaceEntry")

// verifyOwner must perform the caller's current strict native attachment,
// driver and consent proof. It is called repeatedly, never cached by this package.
func fresh(ctx context.Context, s Scope, verifyOwner func() error) error {
	if ctx == nil || verifyOwner == nil || validateScope(s) != nil {
		return errors.New("USB_INTERFACE_CONFIG_SCOPE_INVALID")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := verifyOwner(); e != nil {
		return errors.New("USB_INTERFACE_CONFIG_OWNER_UNPROVEN")
	}
	var table *windows.MibIfTable2
	if windows.GetIfTable2Ex(windows.MibIfEntryNormal, &table) != nil || table == nil {
		return errors.New("USB_INTERFACE_CONFIG_NATIVE_UNREADABLE")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 65536 {
		return errors.New("USB_INTERFACE_CONFIG_NATIVE_UNREADABLE")
	}
	count := 0
	for _, r := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
		if r.InterfaceIndex == s.Index || r.InterfaceLuid == s.LUID || strings.EqualFold(r.InterfaceGuid.String(), s.GUID) {
			count++
			if r.InterfaceIndex != s.Index || r.InterfaceLuid != s.LUID || !strings.EqualFold(r.InterfaceGuid.String(), s.GUID) {
				return errors.New("USB_INTERFACE_CONFIG_MAPPING_CHANGED")
			}
			if s.Role == "host" && (r.Type != 53 || windows.UTF16ToString(r.Alias[:]) != "USB Link Host") {
				return errors.New("USB_INTERFACE_CONFIG_MAPPING_CHANGED")
			}
			if s.Role == "mac" && (r.Type != 53 || windows.UTF16ToString(r.Alias[:]) != "USB Link") {
				return errors.New("USB_INTERFACE_CONFIG_MAPPING_CHANGED")
			}
		}
	}
	if count != 1 {
		return errors.New("USB_INTERFACE_CONFIG_MAPPING_CHANGED")
	}
	return ctx.Err()
}
func getRow(s Scope) (windows.MibIpInterfaceRow, error) {
	r := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: s.LUID}
	if windows.GetIpInterfaceEntry(&r) != nil || r.InterfaceIndex != s.Index || r.InterfaceLuid != s.LUID {
		return r, errors.New("USB_INTERFACE_CONFIG_ROW_UNREADABLE")
	}
	return r, nil
}
func setDad(ctx context.Context, s Scope, before windows.MibIpInterfaceRow, n uint32, verify func() error) error {
	if e := fresh(ctx, s, verify); e != nil {
		return e
	}
	r := before
	r.DadTransmits = n
	r.SitePrefixLength = 0
	code, _, _ := setInterface.Call(uintptr(unsafe.Pointer(&r)))
	if code != 0 {
		return errors.New("USB_INTERFACE_CONFIG_DAD_SET_FAILED")
	}
	if e := fresh(ctx, s, verify); e != nil {
		return e
	}
	after, e := getRow(s)
	if e != nil {
		return e
	}
	if after.DadTransmits != n || after.NlMtu != before.NlMtu || after.ForwardingEnabled != before.ForwardingEnabled || after.WeakHostSend != before.WeakHostSend || after.WeakHostReceive != before.WeakHostReceive || after.Metric != before.Metric || after.UseAutomaticMetric != before.UseAutomaticMetric || after.DisableDefaultRoutes != before.DisableDefaultRoutes {
		return errors.New("USB_INTERFACE_CONFIG_DAD_READBACK_CHANGED")
	}
	return nil
}
func ApplyDADZero(ctx context.Context, dir string, s Scope, verifyOwner func() error) (o Observation, e error) {
	start := time.Now()
	o.Kind = "dad_zero"
	defer func() { recordTiming(s.Role, "dad_apply", start, e, o.Code == "DISABLED") }()
	defer func() {
		o.DurationMS = time.Since(start).Milliseconds()
		if e != nil {
			o.Code = e.Error()
		}
	}()
	if !dadEnabled.Load() {
		o.Code = "DISABLED"
		return o, nil
	}
	finish, lockErr := lockConfig()
	if lockErr != nil {
		e := lockErr
		return o, e
	}
	defer finish()
	if e = fresh(ctx, s, verifyOwner); e != nil {
		return o, e
	}
	r, e := getRow(s)
	if e != nil {
		return o, e
	}
	store, found, e := readConfigReceiptFile(dir)
	if e != nil {
		return o, e
	}
	if !found {
		store = configReceipt{Version: 1}
	}
	if store.RestoreRequested {
		return o, errors.New("USB_INTERFACE_CONFIG_UNINSTALL_PENDING")
	}
	owned := false
	for _, original := range store.DAD {
		if strings.EqualFold(original.Scope.GUID, s.GUID) {
			if original.Scope != s || (r.DadTransmits != 0 && r.DadTransmits != original.Original) {
				return o, errors.New("USB_INTERFACE_CONFIG_DAD_ORIGINAL_CHANGED")
			}
			owned = true
		}
	}
	if !owned {
		if r.DadTransmits > 32 || len(store.DAD) >= 16 {
			return o, errors.New("USB_INTERFACE_CONFIG_DAD_ORIGINAL_UNPROVEN")
		}
		store.DAD = append(store.DAD, dadOriginal{Scope: s, Original: r.DadTransmits})
		if e = writeConfigReceiptFile(dir, store, found); e != nil {
			return o, e
		}
	}
	if r.DadTransmits != 0 {
		if e = setDad(ctx, s, r, 0, verifyOwner); e != nil {
			return o, e
		}
		o.Applied = true
	}
	o.Verified = true
	o.Code = "OK"
	return o, nil
}

// RestoreDADZero consumes only this exact interface's durable obligation after
// fresh authorization and independent original-value readback. It is not a
// general adapter mutation API and must run before an owned adapter is removed.
func RestoreDADZero(ctx context.Context, dir string, s Scope, verifyOwner func() error) (result error) {
	start := time.Now()
	defer func() { recordTiming(s.Role, "dad_restore", start, result, false) }()
	finish, lockErr := lockConfig()
	if lockErr != nil {
		e := lockErr
		return e
	}
	defer finish()
	if e := fresh(ctx, s, verifyOwner); e != nil {
		return e
	}
	store, found, e := readConfigReceiptFile(dir)
	if e != nil || !found {
		return e
	}
	for i, o := range store.DAD {
		if strings.EqualFold(o.Scope.GUID, s.GUID) {
			if o.Scope != s {
				return errors.New("USB_INTERFACE_CONFIG_DAD_ORIGINAL_CHANGED")
			}
			r, e := getRow(s)
			if e != nil {
				return e
			}
			if r.DadTransmits != 0 && r.DadTransmits != o.Original {
				return errors.New("USB_INTERFACE_CONFIG_DAD_EXTERNAL_CHANGE")
			}
			if r.DadTransmits != o.Original {
				if e = setDad(ctx, s, r, o.Original, verifyOwner); e != nil {
					return e
				}
			}
			store.DAD = append(store.DAD[:i], store.DAD[i+1:]...)
			return writeConfigReceiptFile(dir, store, true)
		}
	}
	return nil
}
