//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/platform/windows/wincom"
	"time"
	"unsafe"
)

// VerifyPersistentHostActive is the distinct proof required before re-binding
// the ordinary host journal to a reboot-created address. Merely finding the
// desired IP, a fixed alias, or a persistent setting is insufficient.
func VerifyPersistentActive(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps) (ActiveOwnership, error) {
	return verifyPersistentMode(ctx, dir, s, verifyOwner, profile, "persistent", 0)
}
func verifyPersistentMode(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps, mode string, created int64) (out ActiveOwnership, e error) {
	start := time.Now()
	defer func() { recordTiming(s.Role, "persistent_reuse", start, e, !persistentEnabled.Load()) }()
	if !persistentEnabled.Load() || profile.Read == nil {
		return out, errors.New("USB_PERSISTENT_ACTIVE_PROOF_DISABLED")
	}
	finish, lockErr := lockConfig()
	if lockErr != nil {
		e := lockErr
		return out, e
	}
	defer finish()
	return verifyPersistentModeUnlocked(ctx, dir, s, verifyOwner, profile, mode, created)
}

// Caller holds lockConfig, so the active/Store/original/mapping proof and final
// mapping checkpoint can share one cross-process ownership transaction.
func verifyPersistentModeUnlocked(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps, mode string, created int64) (out ActiveOwnership, e error) {
	if e = fresh(ctx, s, verifyOwner); e != nil {
		return out, e
	}
	receipt, found, e := readConfigReceiptFile(dir)
	if e != nil || !found {
		return out, errors.New("USB_PERSISTENT_RECEIPT_UNPROVEN")
	}
	var owned *persistentOriginal
	for i := range receipt.Persistent {
		if strings.EqualFold(receipt.Persistent[i].Scope.GUID, s.GUID) {
			owned = &receipt.Persistent[i]
		}
	}
	if owned == nil || owned.Scope.Role != s.Role || (s.Role != "host" && !persistentScopeMatches(dir, *owned, s)) || owned.AppliedAddress == nil || owned.Profile == nil {
		return out, errors.New("USB_PERSISTENT_CREATION_READBACK_UNPROVEN")
	}
	// A saved successful creation is an obligation, not a current Store
	// observation. Re-read the exact persistent provider fields before any
	// reboot-created ActiveStore row can rebind its creation stamp.
	if e = verifyPersistentStore(ctx, s, verifyOwner, *owned); e != nil {
		return out, e
	}
	network, category, e := profile.Read(ctx)
	if e != nil || !strings.EqualFold(network, owned.Profile.NetworkGUID) || category != 1 {
		return out, errors.New("USB_PERSISTENT_PROFILE_READBACK_CHANGED")
	}
	if e = fresh(ctx, s, verifyOwner); e != nil {
		return out, e
	}
	r, e := getRow(s)
	if e != nil {
		return out, e
	}
	var table *windows.MibUnicastIpAddressTable
	if windows.GetUnicastIpAddressTable(windows.AF_INET, &table) != nil || table == nil {
		return out, errors.New("USB_PERSISTENT_ACTIVE_TABLE_UNREADABLE")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 65536 {
		return out, errors.New("USB_PERSISTENT_ACTIVE_TABLE_UNREADABLE")
	}
	addresses := make([]activeAddress, 0, table.NumEntries)
	for _, a := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
		v := (*windows.RawSockaddrInet4)(unsafe.Pointer(&a.Address))
		if v.Family != windows.AF_INET {
			return out, errors.New("USB_PERSISTENT_ACTIVE_TABLE_UNREADABLE")
		}
		addresses = append(addresses, activeAddress{Index: a.InterfaceIndex, LUID: a.InterfaceLuid, IP: fmt.Sprintf("%d.%d.%d.%d", v.Addr[0], v.Addr[1], v.Addr[2], v.Addr[3]), Prefix: uint32(a.OnLinkPrefixLength), PrefixOrigin: uint32(a.PrefixOrigin), SuffixOrigin: uint32(a.SuffixOrigin), DAD: uint32(a.DadState), ValidLifetime: a.ValidLifetime, PreferredLifetime: a.PreferredLifetime, Skip: a.SkipAsSource != 0, Created: int64(uint64(a.CreationTimeStamp.HighDateTime)<<32 | uint64(a.CreationTimeStamp.LowDateTime))})
	}
	a, e := acceptActiveMode(s, addresses, r.NlMtu, mode, created)
	if e != nil {
		return out, e
	}
	if e = fresh(ctx, s, verifyOwner); e != nil {
		return out, e
	}
	if e = verifyPersistentStore(ctx, s, verifyOwner, *owned); e != nil {
		return out, e
	}
	last, found, e := readConfigReceiptFile(dir)
	if e != nil || !found || !sameConfigReceipt(last, receipt) {
		return out, errors.New("USB_PERSISTENT_RECEIPT_CHANGED")
	}
	b, e := json.Marshal(owned)
	if e != nil {
		return out, errors.New("USB_PERSISTENT_RECEIPT_UNPROVEN")
	}
	h := sha256.Sum256(b)
	return ActiveOwnership{Scope: s, Created: a.Created, ReceiptSHA256: hex.EncodeToString(h[:]), AddressMode: mode}, nil
}

// Fixed-host compatibility wrapper. Mac and iPad callers use the same strict
// per-instance verifier, never a host journal or an address-derived identity.
func VerifyPersistentHostActive(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps) (ActiveOwnership, error) {
	if s.Role != "host" {
		return ActiveOwnership{}, errors.New("USB_PERSISTENT_HOST_SCOPE_REQUIRED")
	}
	return VerifyPersistentActive(ctx, dir, s, verifyOwner, profile)
}

// A legacy current-session row must still have its exact creation stamp. Only
// the distinct infinite boot proof may authorize a new Created checkpoint.
func VerifyPersistentHostRuntime(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps, created int64) (ActiveOwnership, error) {
	if s.Role != "host" {
		return ActiveOwnership{}, errors.New("USB_PERSISTENT_HOST_SCOPE_REQUIRED")
	}
	return verifyPersistentMode(ctx, dir, s, verifyOwner, profile, "legacy", created)
}

// Presence is only a recovery fence. A saved obligation never authorizes a
// current interface or a Created timestamp; full verification remains required.
func HasPersistentObligation(dir string, s Scope) (bool, error) {
	if _, e := os.Lstat(filepath.Join(dir, configFile)); os.IsNotExist(e) {
		return false, nil
	} else if e != nil {
		return false, errors.New("USB_PERSISTENT_RECEIPT_UNREADABLE")
	}
	finish, lockErr := lockConfig()
	if lockErr != nil {
		e := lockErr
		return false, e
	}
	defer finish()
	if validateScope(s) != nil {
		return false, errors.New("USB_PERSISTENT_SCOPE_INVALID")
	}
	r, found, e := readConfigReceiptFile(dir)
	if e != nil || !found {
		return false, e
	}
	for _, v := range r.Persistent {
		if strings.EqualFold(v.Scope.GUID, s.GUID) {
			if v.Scope.Role != s.Role {
				return false, errors.New("USB_PERSISTENT_SCOPE_CHANGED")
			}
			return true, nil
		}
	}
	return false, nil
}

func verifyRetainedRuntime(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps, created int64, mode string) (ActiveOwnership, error) {
	if s.Role != "mac" && s.Role != "ipad" {
		return ActiveOwnership{}, errors.New("USB_PERSISTENT_SECONDARY_SCOPE_REQUIRED")
	}
	runtimeMode := "retained_runtime"
	if mode == "legacy" {
		runtimeMode = "retained_legacy"
	} else if mode != "persistent" {
		return ActiveOwnership{}, errors.New("USB_PERSISTENT_SECONDARY_MODE_INVALID")
	}
	return verifyPersistentMode(ctx, dir, s, verifyOwner, profile, runtimeMode, created)
}

// verifyPersistentStore is read-only. The current native mapping is proved
// before and after provider access; CIM fields never authorize an interface.
func verifyPersistentStore(ctx context.Context, s Scope, owner func() error, original persistentOriginal) error {
	return wincom.WithApartment(func() error {
		if e := fresh(ctx, s, owner); e != nil {
			return e
		}
		svc, e := connectCIM()
		if e != nil {
			return e
		}
		defer svc.Close()
		iface, mtu, e := persistentInterface(svc, s)
		if e != nil {
			return e
		}
		defer iface.Close()
		dhcp, e := cimUint(iface, "Dhcp", 17)
		if e != nil || dhcp != 0 || mtu != original.DesiredMTU {
			return errors.New("USB_PERSISTENT_STORE_INTERFACE_CHANGED")
		}
		if _, e = readPersistentPolicy(iface); e != nil {
			return e
		}
		address, obj, e := persistentAddresses(svc, s)
		if obj != nil {
			defer obj.Close()
		}
		if e != nil || !addressMatchesBaseline(s, address, original.AppliedAddress) {
			return errors.New("USB_PERSISTENT_STORE_ADDRESS_CHANGED")
		}
		return fresh(ctx, s, owner)
	})
}
