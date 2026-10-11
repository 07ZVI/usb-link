//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"
)

var ownedDADEnabled atomic.Bool

func OwnedDADZeroEnabled() bool     { return ownedDADEnabled.Load() }
func SetOwnedDADZeroEnabled(v bool) { ownedDADEnabled.Store(v) }

// Apply retains the first actual original across disconnects and same-LUID
// index changes. The caller's proof must cover the held official adapter and
// protected owner (plus the actual authorized USB root for Mac/iPad).
func ApplyOwnedDADZero(ctx context.Context, dir string, id OwnedDADIdentity, verifyOwner func() error) (o Observation, result error) {
	start := time.Now()
	o.Kind = "owned_dad_zero"
	defer func() {
		o.DurationMS = time.Since(start).Milliseconds()
		if result != nil {
			o.Code = result.Error()
		}
		recordTiming(id.Scope.Role, "owned_dad_apply", start, result, o.Code == "DISABLED")
	}()
	if !OwnedDADZeroEnabled() {
		o.Code = "DISABLED"
		return o, nil
	}
	done, e := lockConfig()
	if e != nil {
		return o, e
	}
	defer done()
	if !validOwnedDADIdentity(id) {
		return o, errors.New("USB_OWNED_DAD_SOURCE_UNPROVEN")
	}
	if e = fresh(ctx, id.Scope, verifyOwner); e != nil {
		return o, e
	}
	before, e := getRow(id.Scope)
	if e != nil {
		return o, e
	}
	v, found, e := readOwnedDADFile(dir)
	if e != nil {
		return o, e
	}
	if !found {
		v = ownedDADLedger{Version: 1, Originals: []ownedDADOriginal{}}
	}
	index, e := ownedDADAdmission(v, id, before.DadTransmits)
	if e != nil {
		return o, e
	}
	if index < 0 {
		v.Originals = append(v.Originals, ownedDADOriginal{Identity: id, Original: before.DadTransmits})
		if e = writeOwnedDADFile(dir, v, found); e != nil {
			return o, e
		}
	}
	// Check the protected receipt and live row once more directly before writing.
	got, has, e := readOwnedDADFile(dir)
	if e != nil || !has || !sameOwnedDADLedger(v, got) {
		return o, errors.New("USB_OWNED_DAD_INTENT_CHANGED")
	}
	if e = fresh(ctx, id.Scope, verifyOwner); e != nil {
		return o, e
	}
	current, e := getRow(id.Scope)
	if e != nil {
		return o, e
	}
	if current != before {
		return o, errors.New("USB_OWNED_DAD_ROW_CHANGED")
	}
	if before.DadTransmits != 0 {
		if e = setOwnedDad(ctx, id.Scope, before, 0, verifyOwner); e != nil {
			return o, e
		}
		o.Applied = true
	}
	if e = fresh(ctx, id.Scope, verifyOwner); e != nil {
		return o, e
	}
	current, e = getRow(id.Scope)
	if e != nil || current.DadTransmits != 0 {
		return o, errors.New("USB_OWNED_DAD_READBACK_UNPROVEN")
	}
	got, has, e = readOwnedDADFile(dir)
	if e != nil || !has || !sameOwnedDADLedger(v, got) {
		return o, errors.New("USB_OWNED_DAD_INTENT_CHANGED")
	}
	o.Verified = true
	o.Code = "OK"
	return o, nil
}

// Only DadTransmits (and the documented IPv4 input SitePrefixLength=0)
// differs in the setter input. Verify every writable field on readback; exclude
// only fields documented as ignored by SetIpInterfaceEntry.
func setOwnedDad(ctx context.Context, s Scope, before windows.MibIpInterfaceRow, n uint32, owner func() error) error {
	if e := fresh(ctx, s, owner); e != nil {
		return e
	}
	current, e := getRow(s)
	if e != nil {
		return e
	}
	if current != before {
		return errors.New("USB_OWNED_DAD_ROW_CHANGED")
	}
	input := current
	input.DadTransmits = n
	input.SitePrefixLength = 0
	code, _, _ := setInterface.Call(uintptr(unsafe.Pointer(&input)))
	if code != 0 {
		return errors.New("USB_OWNED_DAD_SET_FAILED")
	}
	if e := fresh(ctx, s, owner); e != nil {
		return e
	}
	after, e := getRow(s)
	if e != nil {
		return e
	}
	expected := before
	expected.DadTransmits = n
	if after.SitePrefixLength != 0 && after.SitePrefixLength != before.SitePrefixLength {
		return errors.New("USB_OWNED_DAD_OTHER_FIELDS_CHANGED")
	}
	expected.SitePrefixLength = after.SitePrefixLength
	normalize := func(r *windows.MibIpInterfaceRow) {
		r.MaxReassemblySize = 0
		r.MinRouterAdvertisementInterval = 0
		r.MaxRouterAdvertisementInterval = 0
		r.Connected = 0
		r.SupportsWakeUpPatterns = 0
		r.SupportsNeighborDiscovery = 0
		r.SupportsRouterDiscovery = 0
		r.ReachableTime = 0
		r.TransmitOffload = 0
		r.ReceiveOffload = 0
	}
	normalize(&expected)
	normalize(&after)
	if expected != after {
		return errors.New("USB_OWNED_DAD_OTHER_FIELDS_CHANGED")
	}
	return fresh(ctx, s, owner)
}

func ReadOwnedDADObligations(dir string) ([]OwnedDADIdentity, error) {
	done, e := lockConfig()
	if e != nil {
		return nil, e
	}
	defer done()
	v, _, e := readOwnedDADFile(dir)
	if e != nil {
		return nil, e
	}
	out := make([]OwnedDADIdentity, 0, len(v.Originals))
	for _, o := range v.Originals {
		out = append(out, o.Identity)
	}
	return out, nil
}
func RequestOwnedDADUninstall(dir string) error {
	done, e := lockConfig()
	if e != nil {
		return e
	}
	defer done()
	v, found, e := readOwnedDADFile(dir)
	if e != nil || !found {
		return e
	}
	v.RestoreRequested = true
	return writeOwnedDADFile(dir, v, true)
}
func OwnedDADRestoreRequested(dir string) (bool, error) {
	done, e := lockConfig()
	if e != nil {
		return false, e
	}
	defer done()
	v, found, e := readOwnedDADFile(dir)
	if e != nil || !found {
		return false, e
	}
	return v.RestoreRequested, nil
}
func ConfirmOwnedDADUninstallComplete(dir string) error {
	done, e := lockConfig()
	if e != nil {
		return e
	}
	defer done()
	v, found, e := readOwnedDADFile(dir)
	if e != nil || !found {
		return e
	}
	if len(v.Originals) != 0 {
		return errors.New("USB_OWNED_DAD_ORIGINALS_PENDING")
	}
	return clearOwnedDADFile(dir, v)
}

// Retire is for BEFORE an official factory Open/Create. Absence is independently
// proven here; a caller hint, missing MIB row, CR13 or phantom is insufficient.
func RetireOwnedDADAbsent(ctx context.Context, dir string, id OwnedDADIdentity) error {
	done, e := lockConfig()
	if e != nil {
		return e
	}
	defer done()
	v, found, e := readOwnedDADFile(dir)
	if e != nil || !found {
		return e
	}
	for i, o := range v.Originals {
		if o.Identity == id {
			if e = ownedDADAbsent(ctx, id); e != nil {
				return e
			}
			got, has, e := readOwnedDADFile(dir)
			if e != nil || !has || !sameOwnedDADLedger(v, got) {
				return errors.New("USB_OWNED_DAD_INTENT_CHANGED")
			}
			if e = ownedDADAbsent(ctx, id); e != nil {
				return e
			}
			v.Originals = append(v.Originals[:i], v.Originals[i+1:]...)
			return writeOwnedDADFile(dir, v, true)
		}
	}
	return errors.New("USB_OWNED_DAD_LIFECYCLE_NOT_FOUND")
}

// Restore runs only under the confirmed uninstall coordinator. No adapter is
// opened, created or deleted. Unknown/nonpresent originals remain obligations.
func RestoreOwnedDADForUninstall(ctx context.Context, dir string, verifyOwner func(OwnedDADIdentity) error) error {
	return restoreOwnedDADForUninstall(ctx, dir, nil, verifyOwner)
}
func RestoreOwnedDADZero(ctx context.Context, dir string, id OwnedDADIdentity, verifyOwner func() error) error {
	if !validOwnedDADIdentity(id) || verifyOwner == nil {
		return errors.New("USB_OWNED_DAD_SOURCE_UNPROVEN")
	}
	return restoreOwnedDADForUninstall(ctx, dir, &id, func(current OwnedDADIdentity) error {
		if current != id {
			return errors.New("USB_OWNED_DAD_RESTORE_SCOPE_CHANGED")
		}
		return verifyOwner()
	})
}
func restoreOwnedDADForUninstall(ctx context.Context, dir string, selected *OwnedDADIdentity, verifyOwner func(OwnedDADIdentity) error) error {
	done, e := lockConfig()
	if e != nil {
		return e
	}
	defer done()
	v, found, e := readOwnedDADFile(dir)
	if e != nil || !found {
		return e
	}
	if !v.RestoreRequested || verifyOwner == nil {
		return errors.New("USB_OWNED_DAD_UNINSTALL_UNPROVEN")
	}
	for len(v.Originals) > 0 {
		index := 0
		if selected != nil {
			index = -1
			for i, o := range v.Originals {
				if strings.EqualFold(o.Identity.Scope.GUID, selected.Scope.GUID) && !sameOwnedDADLifecycle(o.Identity, *selected) {
					return errors.New("USB_OWNED_DAD_RESTORE_LIFECYCLE_CHANGED")
				}
				if sameOwnedDADLifecycle(o.Identity, *selected) {
					index = i
					break
				}
			}
			if index < 0 {
				return nil
			}
		}
		original := v.Originals[index]
		id := original.Identity
		current, present, e := ownedDADCurrentScope(ctx, id)
		if e != nil {
			return e
		}
		if !present {
			if e = ownedDADAbsent(ctx, id); e != nil {
				return e
			}
		} else {
			id.Scope = current
			owner := func() error { return verifyOwner(id) }
			if e = fresh(ctx, current, owner); e != nil {
				return e
			}
			row, e := getRow(current)
			if e != nil {
				return e
			}
			if row.DadTransmits != 0 && row.DadTransmits != original.Original {
				return errors.New("USB_OWNED_DAD_EXTERNAL_CHANGE")
			}
			got, has, e := readOwnedDADFile(dir)
			if e != nil || !has || !sameOwnedDADLedger(v, got) {
				return errors.New("USB_OWNED_DAD_INTENT_CHANGED")
			}
			if row.DadTransmits != original.Original {
				if e = setOwnedDad(ctx, current, row, original.Original, owner); e != nil {
					return e
				}
			}
			if e = fresh(ctx, current, owner); e != nil {
				return e
			}
			check, e := getRow(current)
			if e != nil || check.DadTransmits != original.Original {
				return errors.New("USB_OWNED_DAD_RESTORE_READBACK_UNPROVEN")
			}
		}
		got, has, e := readOwnedDADFile(dir)
		if e != nil || !has || !sameOwnedDADLedger(v, got) {
			return errors.New("USB_OWNED_DAD_INTENT_CHANGED")
		}
		if !present {
			if e = ownedDADAbsent(ctx, original.Identity); e != nil {
				return e
			}
		}
		v.Originals = append(v.Originals[:index], v.Originals[index+1:]...)
		if e = writeOwnedDADFile(dir, v, true); e != nil {
			return e
		}
		if selected != nil {
			return nil
		}
	}
	return nil
}
func ownedDADCurrentScope(ctx context.Context, id OwnedDADIdentity) (Scope, bool, error) {
	if ctx == nil || ctx.Err() != nil || !validOwnedDADIdentity(id) {
		return Scope{}, false, errors.New("USB_OWNED_DAD_SOURCE_UNPROVEN")
	}
	var t *windows.MibIfTable2
	if windows.GetIfTable2Ex(windows.MibIfEntryNormal, &t) != nil || t == nil {
		return Scope{}, false, errors.New("USB_OWNED_DAD_MAPPING_UNREADABLE")
	}
	defer windows.FreeMibTable(unsafe.Pointer(t))
	if t.NumEntries > 65536 {
		return Scope{}, false, errors.New("USB_OWNED_DAD_MAPPING_UNBOUNDED")
	}
	s := id.Scope
	count := 0
	for _, r := range unsafe.Slice(&t.Table[0], int(t.NumEntries)) {
		if r.InterfaceLuid == s.LUID || strings.EqualFold(r.InterfaceGuid.String(), s.GUID) {
			count++
			if r.InterfaceLuid != s.LUID || !strings.EqualFold(r.InterfaceGuid.String(), s.GUID) || r.InterfaceIndex == 0 {
				return Scope{}, false, errors.New("USB_OWNED_DAD_LIFECYCLE_CHANGED")
			}
			s.Index = r.InterfaceIndex
		}
	}
	if count > 1 {
		return Scope{}, false, errors.New("USB_OWNED_DAD_MAPPING_AMBIGUOUS")
	}
	return s, count == 1, nil
}
func ownedDADAbsent(ctx context.Context, id OwnedDADIdentity) error {
	if _, present, e := ownedDADCurrentScope(ctx, id); e != nil {
		return e
	} else if present {
		return errors.New("USB_OWNED_DAD_TARGET_REMAINS")
	}
	// Old indices may be reused. Only the original LUID identifies dangling rows.
	var addresses *windows.MibUnicastIpAddressTable
	if windows.GetUnicastIpAddressTable(windows.AF_UNSPEC, &addresses) != nil || addresses == nil {
		return errors.New("USB_OWNED_DAD_ADDRESS_UNREADABLE")
	}
	defer windows.FreeMibTable(unsafe.Pointer(addresses))
	if addresses.NumEntries > 65536 {
		return errors.New("USB_OWNED_DAD_ADDRESS_UNBOUNDED")
	}
	for _, r := range unsafe.Slice(&addresses.Table[0], int(addresses.NumEntries)) {
		if r.InterfaceLuid == id.Scope.LUID {
			return errors.New("USB_OWNED_DAD_ADDRESS_REMAINS")
		}
	}
	// Include installed ghosts and changed classes, not merely PRESENT nodes.
	set, e := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES, 0, "")
	if e != nil {
		return errors.New("USB_OWNED_DAD_INSTALLED_UNREADABLE")
	}
	defer set.Close()
	netClass, _ := windows.GUIDFromString("{4d36e972-e325-11ce-bfc1-08002be10318}")
	for i := 0; i < 65536; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		info, e := set.EnumDeviceInfo(i)
		if e == windows.ERROR_NO_MORE_ITEMS {
			return nil
		}
		if e != nil {
			return errors.New("USB_OWNED_DAD_INSTALLED_UNREADABLE")
		}
		instance, e := set.DeviceInstanceID(info)
		if e != nil {
			return errors.New("USB_OWNED_DAD_INSTALLED_UNREADABLE")
		}
		if strings.EqualFold(instance, id.Instance) {
			return errors.New("USB_OWNED_DAD_INSTALLED_TARGET_REMAINS")
		}
		if info.ClassGUID != netClass {
			continue
		}
		key, e := set.OpenDevRegKey(info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
		if e == windows.ERROR_FILE_NOT_FOUND {
			continue
		}
		if e != nil {
			return errors.New("USB_OWNED_DAD_BINDING_UNREADABLE")
		}
		guid, found, er := readOwnedDADBindingGUID(key)
		windows.RegCloseKey(key)
		if er != nil {
			return er
		}
		if !found {
			continue
		}
		if strings.EqualFold(guid, id.Scope.GUID) {
			return errors.New("USB_OWNED_DAD_INSTALLED_TARGET_REMAINS")
		}
	}
	return errors.New("USB_OWNED_DAD_INSTALLED_UNBOUNDED")
}

func readOwnedDADBindingGUID(key windows.Handle) (string, bool, error) {
	var b [64]uint16
	typ := uint32(0)
	size := uint32(len(b) * 2)
	e := windows.RegQueryValueEx(key, windows.StringToUTF16Ptr("NetCfgInstanceId"), nil, &typ, (*byte)(unsafe.Pointer(&b[0])), &size)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return "", false, nil
	}
	if e != nil || typ != windows.REG_SZ || size < 2 || size%2 != 0 || size > uint32(len(b)*2) || b[size/2-1] != 0 {
		return "", false, errors.New("USB_OWNED_DAD_BINDING_UNREADABLE")
	}
	for _, c := range b[:size/2-1] {
		if c == 0 {
			return "", false, errors.New("USB_OWNED_DAD_BINDING_UNREADABLE")
		}
	}
	guid := windows.UTF16ToString(b[:size/2])
	if !guidPattern.MatchString(guid) {
		return "", false, errors.New("USB_OWNED_DAD_BINDING_UNREADABLE")
	}
	return guid, true, nil
}
