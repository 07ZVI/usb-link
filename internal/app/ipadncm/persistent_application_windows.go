//go:build windows && amd64

package ipadncm

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/ipadsession"
)

// Presence selects stricter recovery; it never proves identity or authorization.
func ipadConfigurationFilesPresent(dir string) (bool, error) {
	for _, leaf := range []string{"usb-ipad-persistent-binding.json", "usb-interface-config.json"} {
		_, e := os.Lstat(filepath.Join(dir, leaf))
		if e == nil {
			return true, nil
		}
		if !os.IsNotExist(e) {
			return true, errors.New("IPAD_CONFIGURATION_METADATA_UNREADABLE")
		}
	}
	return false, nil
}

type ipadConfigurationLease struct {
	dir      string
	binding  interfaceconfig.IPadPersistentBinding
	owner    func() error
	profile  interfaceconfig.ProfileOps
	retained *interfaceconfig.RetainedSecondary
}

func (b *groupingBackend) prepareIPadConfiguration(ctx context.Context, a NetworkAdapter, p ipadsession.Plan, preflight func() (NetworkAdapter, string)) (*ipadConfigurationLease, ipadsession.Plan, error) {
	selected := interfaceconfig.PersistentEnabled() || interfaceconfig.DADZeroEnabled()
	present, e := ipadConfigurationFilesPresent(b.dir)
	if e != nil {
		return nil, p, e
	}
	if !selected && !present {
		return nil, p, nil
	}
	v, found, e := interfaceconfig.ReadIPadPersistentBinding(b.dir)
	if e != nil {
		return nil, p, e
	}
	if !found && present {
		_, pending, restore, e := interfaceconfig.ReadIPadOriginalsState(b.dir)
		if e != nil {
			return nil, p, e
		}
		if pending || restore {
			return nil, p, errors.New("IPAD_CONFIGURATION_ORIGINALS_WITHOUT_BINDING")
		}
		if !selected {
			return nil, p, nil
		} // A consumed empty store grants no authority.
	}
	if p.Version != 5 || p.ServerIP != "10.6.9.1" || !netconfig.NativeNetworkEnabled() {
		return nil, p, errors.New("IPAD_CONFIGURATION_NATIVE_SHARED_HOST_REQUIRED")
	}
	scope := interfaceconfig.Scope{Role: "ipad", GUID: p.GUID, Index: p.Index, LUID: p.LUID}
	if len(b.mode.Before.Devices) != 1 || !b.mode.Before.Devices[0].USBDescriptorIdentityVerified || a.instanceID == "" {
		return nil, p, errors.New("IPAD_CONFIGURATION_FRESH_DESCRIPTOR_UNPROVEN")
	}
	candidate := interfaceconfig.IPadPersistentBinding{Version: 1, Root: b.networkRoot(), Driver: b.networkDriver(), Instance: a.instanceID, SerialSHA256: b.mode.Before.Devices[0].USBSerialSHA256, Scope: scope, State: "pending", Plan: p, Persistent: interfaceconfig.PersistentEnabled()}
	if found {
		if !interfaceconfig.PersistentEnabled() || v.State != "ready" || v.Scope != scope || v.Root != candidate.Root || v.Driver != candidate.Driver || v.Instance != candidate.Instance || v.SerialSHA256 != candidate.SerialSHA256 {
			return nil, p, errors.New("IPAD_CONFIGURATION_EXISTING_BINDING_NOT_REUSABLE")
		}
		// HostFlags remain the first original, rather than re-capturing enabled flags.
		p.HostFlags = v.Plan.HostFlags
	}
	owner := func() error {
		fresh, er := preflight()
		if er != "" {
			return errors.New(er)
		}
		if fresh.key != a.key || fresh.instanceID != a.instanceID || fresh.InterfaceIndex != scope.Index || fresh.luid != scope.LUID {
			return errors.New("IPAD_CONFIGURATION_CURRENT_SCOPE_CHANGED")
		}
		return verifyIPadPersistentNative(ctx, candidate)
	}
	if e = owner(); e != nil {
		return nil, p, e
	}
	lease := &ipadConfigurationLease{dir: b.dir, owner: owner, profile: interfaceconfig.IPadProfileOps(scope, owner, nil)}
	if found {
		lease.binding = v
		lease.retained, e = interfaceconfig.RetainSecondarySession(ctx, b.dir, scope, owner, lease.profile, v.Plan.CreatedAt, v.Plan.AddressMode, v.Plan.PersistentSHA256)
		if e != nil {
			return nil, p, e
		}
		p.Version = 6
		p.CreatedAt = lease.retained.Created()
		p.AddressMode = lease.retained.AddressMode()
		p.PersistentSHA256 = lease.retained.ReceiptSHA256()
		next := v
		next.Plan = p
		if e = interfaceconfig.CheckpointIPadPersistentReady(ctx, b.dir, v, next, owner, lease.profile); e != nil {
			return nil, p, e
		}
		lease.binding = next
		return lease, p, nil
	}
	// First capture is not permitted to overwrite/adopt an existing Active row.
	if e = verifyApplicationAddressAbsent(p); e != nil {
		return nil, p, e
	}
	candidate.Plan = p
	lease.binding = candidate
	if e = interfaceconfig.CaptureIPadPersistentIntent(ctx, b.dir, candidate, owner); e != nil {
		return nil, p, e
	}
	return lease, p, nil
}
func (l *ipadConfigurationLease) beforeAddress(ctx context.Context) error {
	if l == nil {
		return nil
	}
	_, e := interfaceconfig.ApplyDADZero(ctx, l.dir, l.binding.Scope, l.owner)
	return e
}
func (l *ipadConfigurationLease) afterAddress(ctx context.Context, p ipadsession.Plan) (ipadsession.Plan, error) {
	if l == nil || l.retained != nil {
		return p, nil
	}
	next := l.binding
	next.Plan = p
	next.State = "address"
	if !next.Persistent {
		next.State = "ephemeral"
	}
	if e := interfaceconfig.CheckpointIPadPersistentAddress(ctx, l.dir, l.binding, next, l.owner); e != nil {
		return p, e
	}
	l.binding = next
	if !next.Persistent {
		return p, nil
	}
	retained, e := interfaceconfig.CapturePersistentSecondaryAfterAddress(ctx, l.dir, next.Scope, l.owner, l.profile, p.CreatedAt)
	if e != nil {
		return p, e
	}
	if retained == nil {
		return p, errors.New("IPAD_PERSISTENT_CAPTURE_DISABLED")
	}
	p.Version = 6
	p.AddressMode = retained.AddressMode()
	p.PersistentSHA256 = retained.ReceiptSHA256()
	ready := next
	ready.State = "ready"
	ready.Plan = p
	if e = interfaceconfig.CheckpointIPadPersistentReady(ctx, l.dir, next, ready, l.owner, l.profile); e != nil {
		return p, e
	}
	l.binding = ready
	l.retained = retained
	return p, nil
}
func matchingIPadApplicationBinding(v interfaceconfig.IPadPersistentBinding, j applicationJournal) bool {
	return strings.EqualFold(v.Root, j.Root) && strings.EqualFold(v.Driver, j.Driver) && v.Scope.Index == j.Plan.Index && v.Scope.LUID == j.Plan.LUID && strings.EqualFold(v.Scope.GUID, j.Plan.GUID) && j.Plan.HostFlags != nil && v.Plan.HostFlags != nil && *j.Plan.HostFlags == *v.Plan.HostFlags
}

// Cleanup uses only the protected completed or pending original and fresh
// exact native nodes, not a disappearing live USB/peer/consent callback.
func recoverIPadConfigurationBeforeAddress(ctx context.Context, dir string, j applicationJournal) (bool, error) {
	present, e := ipadConfigurationFilesPresent(dir)
	if e != nil || !present {
		return false, e
	}
	v, found, e := interfaceconfig.ReadIPadPersistentBinding(dir)
	if e != nil {
		return false, e
	}
	if !found {
		_, pending, restore, e := interfaceconfig.ReadIPadOriginalsState(dir)
		if e != nil {
			return false, e
		}
		if !pending && (j.Plan.Version != 6 || restore && verifyApplicationAddressAbsent(j.Plan) == nil) {
			return false, nil
		}
		return false, errors.New("IPAD_CONFIGURATION_RECOVERY_BINDING_UNPROVEN")
	}
	if !matchingIPadApplicationBinding(v, j) {
		return false, errors.New("IPAD_CONFIGURATION_RECOVERY_BINDING_UNPROVEN")
	}
	owner := func() error { return verifyIPadPersistentNative(ctx, v) }
	if e = owner(); e != nil {
		return false, e
	}
	if e = interfaceconfig.RestoreDADZero(ctx, dir, v.Scope, owner); e != nil {
		return false, e
	}
	if v.State == "ready" {
		if j.Plan.Version != 6 || j.Plan.PersistentSHA256 != v.Plan.PersistentSHA256 || j.Plan.CreatedAt != v.Plan.CreatedAt || j.Plan.AddressMode != v.Plan.AddressMode {
			return false, errors.New("IPAD_CONFIGURATION_COMPLETED_PLAN_CHANGED")
		}
		// No ordinary stop consumes PersistentStore/NLA originals or deletes address.
		if e = interfaceconfig.VerifyIPadPersistentCleanup(ctx, dir, v, owner, interfaceconfig.IPadProfileOps(v.Scope, owner, nil)); e != nil {
			return false, e
		}
		return true, nil
	}
	if v.State == "restoring" {
		return false, errors.New("IPAD_CONFIGURATION_UNINSTALL_PENDING")
	}
	if e = interfaceconfig.RestorePersistent(ctx, dir, v.Scope, owner, interfaceconfig.IPadProfileOps(v.Scope, owner, nil)); e != nil {
		return false, e
	}
	return false, nil
}
func finishIPadFailedApplication(ctx context.Context, dir string, j applicationJournal) error {
	present, e := ipadConfigurationFilesPresent(dir)
	if e != nil || !present {
		return e
	}
	v, found, e := interfaceconfig.ReadIPadPersistentBinding(dir)
	if e != nil {
		return e
	}
	if !found {
		_, pending, _, e := interfaceconfig.ReadIPadOriginalsState(dir)
		if e != nil {
			return e
		}
		if pending {
			return errors.New("IPAD_CONFIGURATION_RECOVERY_BINDING_MISSING")
		}
		return nil
	}
	if v.State == "ready" {
		return nil
	}
	if !matchingIPadApplicationBinding(v, j) {
		return errors.New("IPAD_CONFIGURATION_RECOVERY_BINDING_CHANGED")
	}
	owner := func() error { return verifyIPadPersistentNative(ctx, v) }
	if e := verifyApplicationAddressAbsent(j.Plan); e != nil {
		return e
	}
	return interfaceconfig.FinishIPadFailedIntent(ctx, dir, v, owner)
}
func verifyApplicationAddressAbsent(p ipadsession.Plan) error {
	r := addressRow(p)
	e := windows.GetUnicastIpAddressEntry(&r)
	if e != windows.ERROR_NOT_FOUND && e != windows.ERROR_FILE_NOT_FOUND {
		return errors.New("IPAD_CONFIGURATION_ADDRESS_ABSENCE_UNPROVEN")
	}
	return nil
}
