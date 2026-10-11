//go:build windows && amd64

package ipadncm

import (
	"context"
	"errors"
	"log"
	"strings"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/transport/ipadsession"
)

// This is a DAD-only operation, independent of native_network/persistent.
// Descriptor provenance comes from the actual authorized connection; every
// mutation rechecks the exact current physical root, UsbNcm child and mapping.
func (b *groupingBackend) applyOwnedIPadDAD(ctx context.Context, a NetworkAdapter, p ipadsession.Plan, preflight func() (NetworkAdapter, string)) error {
	if !interfaceconfig.OwnedDADZeroEnabled() {
		return nil
	}
	if len(b.mode.Before.Devices) != 1 || !b.mode.Before.Devices[0].USBDescriptorIdentityVerified || b.j.RootID == "" || a.instanceID == "" || preflight == nil {
		return errors.New("IPAD_OWNED_DAD_DESCRIPTOR_UNPROVEN")
	}
	id := interfaceconfig.OwnedDADIdentity{Scope: interfaceconfig.Scope{Role: "ipad", GUID: p.GUID, Index: p.Index, LUID: p.LUID}, Instance: a.instanceID, RootInstance: b.j.RootID, Driver: b.j.DriverKey, Serial: b.mode.Before.Devices[0].USBSerialSHA256}
	owner := func() error {
		fresh, code := preflight()
		if code != "" {
			return errors.New(code)
		}
		if fresh.key != a.key || fresh.instanceID != id.Instance || fresh.InterfaceIndex != id.Scope.Index || fresh.luid != id.Scope.LUID {
			return errors.New("IPAD_OWNED_DAD_CURRENT_SCOPE_CHANGED")
		}
		return verifyOwnedIPadDADMapping(ctx, id)
	}
	// Identity failure retains the original connection's strict rejection. Only
	// ledger/value/write failures may fall back to its normal Preferred wait.
	if e := owner(); e != nil {
		return e
	}
	observation, e := interfaceconfig.ApplyOwnedDADZero(ctx, b.dir, id, owner)
	if check := owner(); check != nil {
		return check
	}
	if e != nil {
		log.Printf("IPAD_OWNED_DAD_DEGRADED: %s", observation.Code)
	}
	return nil
}
func verifyOwnedIPadDADMapping(ctx context.Context, id interfaceconfig.OwnedDADIdentity) error {
	if id.Scope.Role != "ipad" || id.RootInstance == "" || id.Driver == "" || id.Serial == "" {
		return errors.New("IPAD_OWNED_DAD_SCOPE_UNPROVEN")
	}
	v := interfaceconfig.IPadPersistentBinding{Root: id.RootInstance, Driver: id.Driver, Instance: id.Instance, SerialSHA256: id.Serial, Scope: id.Scope}
	for pass := 0; pass < 2; pass++ {
		if e := verifyIPadPersistentNative(ctx, v); e != nil {
			return e
		}
	}
	return nil
}

// Local confirmed uninstall only: saved metadata grants no live consent.
// Read actual descriptors before accepting the exact protected serial binding.
func VerifyOwnedIPadDADNative(ctx context.Context, id interfaceconfig.OwnedDADIdentity) error {
	if e := verifyOwnedIPadDADMapping(ctx, id); e != nil {
		return e
	}
	current := inventory(ctx)
	if current.Error != "" || len(current.Devices) != 1 || !current.Devices[0].USBDescriptorIdentityVerified || current.Devices[0].USBSerialSHA256 != id.Serial || !strings.EqualFold(exactIPadRoot(current), id.RootInstance) {
		return errors.New("IPAD_OWNED_DAD_CURRENT_SERIAL_UNPROVEN")
	}
	return verifyOwnedIPadDADMapping(ctx, id)
}

// All ordinary disconnects are no-ops. A confirmed uninstall has already
// durably requested restoration before stopping the Session-0 owner.
func RestoreOwnedIPadDADForClose(ctx context.Context, dir, root, driver string, p ipadsession.Plan) error {
	requested, e := interfaceconfig.OwnedDADRestoreRequested(dir)
	if e != nil || !requested {
		return e
	}
	ids, e := interfaceconfig.ReadOwnedDADObligations(dir)
	if e != nil {
		return e
	}
	for _, original := range ids {
		if original.Scope.Role != "ipad" {
			continue
		}
		if !strings.EqualFold(original.Scope.GUID, p.GUID) {
			continue
		}
		if original.Scope.LUID != p.LUID || original.RootInstance != root || original.Driver != driver {
			return errors.New("IPAD_OWNED_DAD_CLOSE_SCOPE_CHANGED")
		}
		current := original
		current.Scope.Index = p.Index
		return interfaceconfig.RestoreOwnedDADZero(ctx, dir, current, func() error { return VerifyOwnedIPadDADNative(ctx, current) })
	}
	return nil
}
