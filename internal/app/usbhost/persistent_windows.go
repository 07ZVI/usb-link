//go:build windows && amd64

package usbhost

import (
	"bytes"
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/transport/wintun"
	"sync/atomic"
)

var errOwnedPersistentOpen = fmt.Errorf("USB_HOST_OWNED_PERSISTENT_OPEN")
var persistentRestoreOnClose atomic.Bool

// Only the already-confirmed uninstall path selects this. Ordinary stop/update
// keeps PersistentStore obligations; the option is not a mutation authorization.
func RequestPersistentRestoreOnClose() { persistentRestoreOnClose.Store(true) }
func hostScope(p journal) interfaceconfig.Scope {
	return interfaceconfig.Scope{Role: "host", GUID: usbaddress.HostGUID, Index: p.Index, LUID: p.LUID}
}
func hostProofMode(p journal) string {
	if p.Version == 2 && p.AddressMode == "persistent" {
		return "persistent"
	}
	return ""
}
func hostOwnedLifetime(p journal, v, preferred uint32, skip bool) bool {
	if p.Version == 1 {
		return v <= 3600 && preferred <= 3600
	}
	if p.Version != 2 || skip {
		return false
	}
	if p.AddressMode == "legacy" {
		return v <= 3600 && preferred <= 3600
	}
	return p.AddressMode == "persistent" && v == 0xffffffff && preferred == 0xffffffff
}
func verifyHostConfigScope(s interfaceconfig.Scope) error {
	if s.Role != "host" || s.GUID != usbaddress.HostGUID {
		return fmt.Errorf("USB_HOST_PERSISTENT_SCOPE_CHANGED")
	}
	r, present, e := findHost()
	if e != nil || !present || r.InterfaceIndex != s.Index || r.InterfaceLuid != s.LUID {
		return fmt.Errorf("USB_HOST_PERSISTENT_MAPPING_CHANGED")
	}
	return netconfig.VerifySharedHostIdentityNative(s.Index)
}

// This is only an input to fixed read-only/exact-network NLM operations. It is
// never published as readiness or used to replace the protected receipt proof.
func hostProfileProof(s interfaceconfig.Scope) (usbaddress.InterfaceProof, error) {
	if e := verifyHostConfigScope(s); e != nil {
		return usbaddress.InterfaceProof{}, e
	}
	p := journal{GUID: usbaddress.HostGUID, Index: s.Index, LUID: s.LUID}
	r := row(p)
	if windows.GetUnicastIpAddressEntry(&r) != nil || stamp(r) <= 0 {
		return usbaddress.InterfaceProof{}, fmt.Errorf("USB_HOST_PROFILE_ADDRESS_UNPROVEN")
	}
	mode := ""
	if r.ValidLifetime == 0xffffffff && r.PreferredLifetime == 0xffffffff {
		mode = "persistent"
	}
	proof := usbaddress.InterfaceProof{Index: s.Index, LUID: s.LUID, GUID: usbaddress.HostGUID, Role: "host", Created: stamp(r), AddressMode: mode}
	if e := usbaddress.VerifyProofs([]usbaddress.InterfaceProof{proof}); e != nil {
		return usbaddress.InterfaceProof{}, e
	}
	return proof, nil
}
func hostProfileOps(s interfaceconfig.Scope) interfaceconfig.ProfileOps {
	logger := log.New(os.Stderr, "USB host profile: ", 0)
	return interfaceconfig.ProfileOps{
		Read: func(ctx context.Context) (string, uint32, error) {
			p, e := hostProfileProof(s)
			if e != nil {
				return "", 0, e
			}
			return netconfig.ReadPrivateProfileNative(ctx, p, logger)
		},
		SetPrivateExpected: func(ctx context.Context, g string, n uint32) error {
			p, e := hostProfileProof(s)
			if e != nil {
				return e
			}
			return netconfig.SetPrivateProfileWithOriginalNative(ctx, p, g, n, logger)
		},
		Restore: func(ctx context.Context, g string, n uint32) error {
			p, e := hostProfileProof(s)
			if e != nil {
				return e
			}
			return netconfig.RestorePrivateProfileNative(ctx, p, g, n, logger)
		},
	}
}
func observePersistentHost(ctx context.Context, dir string, p journal, s interfaceconfig.Scope) (interfaceconfig.ActiveOwnership, error) {
	r := row(journal{Index: s.Index, LUID: s.LUID})
	if windows.GetUnicastIpAddressEntry(&r) != nil {
		return interfaceconfig.ActiveOwnership{}, fmt.Errorf("USB_HOST_PERSISTENT_ACTIVE_UNREADABLE")
	}
	verify := func() error { return verifyHostConfigScope(s) }
	if stamp(r) == p.Created && r.ValidLifetime <= 3600 && r.PreferredLifetime <= 3600 {
		return interfaceconfig.VerifyPersistentHostRuntime(ctx, dir, s, verify, hostProfileOps(s), p.Created)
	}
	return interfaceconfig.VerifyPersistentHostActive(ctx, dir, s, verify, hostProfileOps(s))
}
func checkpointPersistentHost(ctx context.Context, dir, path string, b []byte, p journal, index uint32, luid uint64) error {
	s := interfaceconfig.Scope{Role: "host", GUID: usbaddress.HostGUID, Index: index, LUID: luid}
	first, e := observePersistentHost(ctx, dir, p, s)
	if e != nil {
		return e
	}
	last, e := observePersistentHost(ctx, dir, p, s)
	if e != nil {
		return e
	}
	next, e := planPersistentHostMapping(p, first, last)
	if e != nil {
		return e
	}
	fresh, e := readHostDiagnosticJournal(path)
	if e != nil || !bytes.Equal(fresh, b) {
		return fmt.Errorf("USB_HOST_PERSISTENT_JOURNAL_CHANGED")
	}
	if e = checkpointMapping(p, next, func(n journal) error { return save(path, n, true) }, func() ([]byte, error) { return readHostDiagnosticJournal(path) }); e != nil {
		return e
	}
	live.Lock()
	live.recovery = map[string]any{"mode": "persistent_owned_reuse", "mapping_changed": p.Index != next.Index || p.LUID != next.LUID, "created_rebound": p.Created != next.Created, "verified": true}
	live.Unlock()
	return nil
}
func openPersistentHost(ctx context.Context, dir, dll string) (*wintun.Device, journal, error) {
	b, p, e := readPersistentFactoryJournal(dir)
	if e != nil || p.Version != 2 {
		return nil, journal{}, fmt.Errorf("USB_HOST_PERSISTENT_JOURNAL_UNPROVEN")
	}
	s := hostScope(p)
	verify := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		fresh, actual, e := readPersistentFactoryJournal(dir)
		if e != nil || actual != p || !bytes.Equal(fresh, b) {
			return fmt.Errorf("USB_HOST_PERSISTENT_JOURNAL_CHANGED")
		}
		factory, found, e := readPersistentFactory(dir)
		if e != nil {
			return e
		}
		if found {
			if factory.State != "ready" || factory.Source != p {
				return fmt.Errorf("USB_HOST_FACTORY_OPEN_BINDING_CHANGED")
			}
			if e = exactHostFactoryOriginal(dir, factory); e != nil {
				return e
			}
			if e = factoryNative(factory, p.Index, p.LUID); e != nil {
				return e
			}
		}
		proof, e := observePersistentHost(ctx, dir, p, s)
		if e != nil {
			return e
		}
		if proof.Created != p.Created || proof.AddressMode != p.AddressMode || proof.ReceiptSHA256 != p.PersistentSHA256 {
			return fmt.Errorf("USB_HOST_PERSISTENT_OPEN_PROOF_CHANGED")
		}
		return nil
	}
	if e = verify(); e != nil {
		return nil, journal{}, e
	}
	pin, e := netconfig.PinVerifiedWintunNative(dll, log.New(os.Stderr, "USB host: ", 0))
	if e != nil {
		return nil, journal{}, e
	}
	defer pin.Close()
	d, e := wintun.OpenOwnedPersistentHost(dll, p.Index, p.LUID, verify)
	return d, p, e
}
func closePersistentHost(dir string, p journal, d *wintun.Device) error {
	defer d.Close()
	ctx := context.Background()
	requested, e := interfaceconfig.PersistentRestoreRequested(dir)
	if e != nil {
		return e
	}
	if !persistentRestoreOnClose.Load() && !requested {
		// Wintun creator Close retires PnP asynchronously. Preserve the immutable
		// original Store plus an exact closed factory obligation BEFORE Close.
		if e = markPersistentHostFactoryClosed(ctx, dir, p, d); e != nil {
			return e
		}
		s := hostScope(p)
		return interfaceconfig.RestoreDADZero(ctx, dir, s, func() error { return verifyHostConfigScope(s) })
	}
	return restorePersistentHostFactory(ctx, dir, p, d)
}
