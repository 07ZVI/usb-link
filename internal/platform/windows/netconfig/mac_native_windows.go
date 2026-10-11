//go:build windows && amd64

package netconfig

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime"
	"strings"
	"suhang/usbnet/internal/platform/windows/wincom"
	"suhang/usbnet/internal/transport/usbaddress"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The native address API does not switch DHCP policy. Require the existing
// owned Wintun adapter to have DHCP disabled rather than modifying undocumented
// DHCP APIs or confusing registry-only changes with active configuration.
func nativeMacDHCPDisabled(p usbaddress.InterfaceProof) error {
	size := uint32(16 * 1024)
	for tries := 0; tries < 3; tries++ {
		if size == 0 || size > 4*1024*1024 {
			return errors.New("USB_NATIVE_MAC_ADAPTER_TABLE_LIMIT")
		}
		b := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_INCLUDE_ALL_INTERFACES|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return errors.New("USB_NATIVE_MAC_ADAPTER_TABLE_UNREADABLE")
		}
		count := 0
		for a, n := first, 0; a != nil; a, n = a.Next, n+1 {
			if n >= 65536 {
				return errors.New("USB_NATIVE_MAC_ADAPTER_TABLE_LIMIT")
			}
			if a.Luid == p.LUID || a.IfIndex == p.Index {
				count++
				if a.Luid != p.LUID || a.IfIndex != p.Index || a.Flags&4 != 0 {
					return errors.New("USB_NATIVE_MAC_DHCP_NOT_DISABLED")
				}
			}
		}
		runtime.KeepAlive(b)
		if count != 1 {
			return errors.New("USB_NATIVE_MAC_ADAPTER_TABLE_AMBIGUOUS")
		}
		return nil
	}
	return errors.New("USB_NATIVE_MAC_ADAPTER_TABLE_CHANGED")
}

func nativeIPCall(name string, p unsafe.Pointer) error {
	proc := macMTUIPHelper.NewProc(name)
	if err := proc.Find(); err != nil {
		return errors.New("USB_NATIVE_NETWORK_API_UNAVAILABLE")
	}
	rc, _, _ := proc.Call(uintptr(p))
	if rc != 0 {
		return fmt.Errorf("USB_NATIVE_NETWORK_API_%s_%d", name, rc)
	}
	return nil
}

// SetupMacNetworkNative is entered only after the gateway barrier, durable
// session journal, and ConfigurationLock. It configures the same active /32
// route and source address as SharedProfileScripts; no gateway/DNS is added.
func SetupMacNetworkNative(ctx context.Context, p usbaddress.InterfaceProof, mtu int, token, profile string, sharedHost bool, proofs []usbaddress.InterfaceProof, beforeAddress func(usbaddress.InterfaceProof) error, logger *log.Logger) error {
	return setupMacNetworkNative(ctx, p, mtu, token, profile, sharedHost, proofs, beforeAddress, nil, logger)
}

// SetupMacNetworkRetainedNative skips only creation and DAD wait for a retained
// persistent /32 address. Its callback must verify the private retained lease,
// protected original receipt and fresh full address observation. It does not
// skip current identity, DHCP/interface policy, conflict, route or rule gates.
func SetupMacNetworkRetainedNative(ctx context.Context, p usbaddress.InterfaceProof, mtu int, token, profile string, sharedHost bool, proofs []usbaddress.InterfaceProof, beforeAddress, verifyRetainedAddress func(usbaddress.InterfaceProof) error, logger *log.Logger) error {
	if !sharedHost || mtu != 1500 || verifyRetainedAddress == nil {
		return errors.New("USB_NATIVE_MAC_RETAINED_PLAN_INVALID")
	}
	return setupMacNetworkNative(ctx, p, mtu, token, profile, sharedHost, proofs, beforeAddress, verifyRetainedAddress, logger)
}

func setupMacNetworkNative(ctx context.Context, p usbaddress.InterfaceProof, mtu int, token, profile string, sharedHost bool, proofs []usbaddress.InterfaceProof, beforeAddress, verifyRetainedAddress func(usbaddress.InterfaceProof) error, logger *log.Logger) error {
	if profile != usbaddress.Unified || !idPattern.MatchString(token) || mtu < 576 || mtu > 1500 {
		return errors.New("USB_NATIVE_MAC_PLAN_INVALID")
	}
	if err := nativeMacScope(ctx, p); err != nil {
		return err
	}
	if verifyRetainedAddress != nil {
		if err := verifyRetainedAddress(p); err != nil {
			return err
		}
	}
	if err := nativeStep(logger, "firewall_provider_preflight", func() error {
		return withFirewall(ctx, func(svc *wincom.Dispatch) error {
			return nativeFirewallCreationPreflight(svc)
		})
	}); err != nil {
		return err
	}
	if err := nativeStep(logger, "mac_subnet_conflict", func() error { return usbaddress.VerifyNoForeignSubnet(p.Index, p.GUID, proofs) }); err != nil {
		return err
	}
	local := [4]byte{10, 6, 9, 1}
	if sharedHost {
		if _, _, err := VirtualHostMacScripts(p.Index, p.GUID, mtu, token, proofs); err != nil {
			return err
		}
		local = [4]byte{10, 6, 9, 253}
	}
	if err := nativeStep(logger, "mac_interface", func() error {
		if err := nativeMacDHCPDisabled(p); err != nil {
			return err
		}
		before := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
		if err := windows.GetIpInterfaceEntry(&before); err != nil {
			return errors.New("USB_NATIVE_MAC_INTERFACE_UNREADABLE")
		}
		if before.InterfaceIndex != p.Index {
			return errors.New("USB_NATIVE_MAC_INTERFACE_CHANGED")
		}
		row := before
		row.SitePrefixLength = 0
		row.NlMtu = uint32(mtu)
		row.Metric = 5000
		row.UseAutomaticMetric = 0
		if sharedHost {
			row.ForwardingEnabled = 1
			row.WeakHostSend = 1
			row.WeakHostReceive = 1
		}
		if err := nativeMacScope(ctx, p); err != nil {
			return err
		}
		if err := nativeIPCall("SetIpInterfaceEntry", unsafe.Pointer(&row)); err != nil {
			return err
		}
		got := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
		if windows.GetIpInterfaceEntry(&got) != nil || got.InterfaceIndex != p.Index || got.NlMtu != row.NlMtu || got.Metric != row.Metric || got.UseAutomaticMetric != 0 || got.ForwardingEnabled != row.ForwardingEnabled || got.WeakHostSend != row.WeakHostSend || got.WeakHostReceive != row.WeakHostReceive || got.DadTransmits != before.DadTransmits || got.DisableDefaultRoutes != before.DisableDefaultRoutes || got.RouterDiscoveryBehavior != before.RouterDiscoveryBehavior {
			return errors.New("USB_NATIVE_MAC_INTERFACE_READBACK_FAILED")
		}
		return nativeMacScope(ctx, p)
	}); err != nil {
		return err
	}
	if beforeAddress != nil {
		if err := beforeAddress(p); err != nil {
			return err
		}
	}
	if err := nativeStep(logger, "mac_address", func() error {
		if err := nativeMacScope(ctx, p); err != nil {
			return err
		}
		if err := usbaddress.VerifyNoForeignSubnet(p.Index, p.GUID, proofs); err != nil {
			return err
		}
		return runMacAddressPhase(verifyRetainedAddress != nil, func() error {
			if err := verifyRetainedAddress(p); err != nil {
				return err
			}
			return nativeMacScope(ctx, p)
		}, func() error {
			row := windows.MibUnicastIpAddressRow{}
			init := macMTUIPHelper.NewProc("InitializeUnicastIpAddressEntry")
			if init.Find() != nil {
				return errors.New("USB_NATIVE_NETWORK_API_UNAVAILABLE")
			}
			init.Call(uintptr(unsafe.Pointer(&row)))
			row.InterfaceLuid = p.LUID
			row.InterfaceIndex = p.Index
			row.PrefixOrigin = 1
			row.SuffixOrigin = 1
			row.OnLinkPrefixLength = 32
			if sharedHost {
				row.SkipAsSource = 1
			}
			a := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
			a.Family = windows.AF_INET
			a.Addr = local
			check := row
			err := windows.GetUnicastIpAddressEntry(&check)
			if err != windows.ERROR_NOT_FOUND && err != windows.ERROR_FILE_NOT_FOUND {
				return errors.New("USB_NATIVE_MAC_ADDRESS_NOT_ABSENT")
			}
			if err := nativeMacScope(ctx, p); err != nil {
				return err
			}
			if err := nativeIPCall("CreateUnicastIpAddressEntry", unsafe.Pointer(&row)); err != nil {
				return err
			}
			deadline := time.NewTimer(15 * time.Second)
			defer deadline.Stop()
			poll := time.NewTicker(100 * time.Millisecond)
			defer poll.Stop()
			for {
				check = row
				if err := windows.GetUnicastIpAddressEntry(&check); err != nil {
					return errors.New("USB_NATIVE_MAC_ADDRESS_READBACK_FAILED")
				}
				if check.InterfaceIndex != p.Index || check.InterfaceLuid != p.LUID || check.OnLinkPrefixLength != 32 || check.PrefixOrigin != 1 || check.SuffixOrigin != 1 || check.SkipAsSource != row.SkipAsSource {
					return errors.New("USB_NATIVE_MAC_ADDRESS_CHANGED")
				}
				if check.DadState == 2 {
					return errors.New("USB_NATIVE_MAC_ADDRESS_DUPLICATE")
				}
				if check.DadState == 4 {
					return nativeMacScope(ctx, p)
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-deadline.C:
					return errors.New("USB_NATIVE_MAC_ADDRESS_NOT_READY")
				case <-poll.C:
				}
			}
		})
	}); err != nil {
		return err
	}
	if err := nativeStep(logger, "mac_peer_route", func() error {
		if err := nativeMacScope(ctx, p); err != nil {
			return err
		}
		row := windows.MibIpForwardRow2{}
		// InitializeIpForwardEntry is void; do not interpret a return register.
		proc := macMTUIPHelper.NewProc("InitializeIpForwardEntry")
		if proc.Find() != nil {
			return errors.New("USB_NATIVE_NETWORK_API_UNAVAILABLE")
		}
		proc.Call(uintptr(unsafe.Pointer(&row)))
		row.InterfaceLuid = p.LUID
		row.InterfaceIndex = p.Index
		row.DestinationPrefix.PrefixLength = 32
		row.Metric = 5000
		row.Protocol = 3
		a := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.DestinationPrefix.Prefix))
		a.Family = windows.AF_INET
		a.Addr = [4]byte{10, 6, 9, 2}
		n := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.NextHop))
		n.Family = windows.AF_INET
		check := row
		err := windows.GetIpForwardEntry2(&check)
		if err != windows.ERROR_NOT_FOUND && err != windows.ERROR_FILE_NOT_FOUND {
			return errors.New("USB_NATIVE_MAC_ROUTE_NOT_ABSENT")
		}
		if err := nativeIPCall("CreateIpForwardEntry2", unsafe.Pointer(&row)); err != nil {
			return err
		}
		check = row
		if windows.GetIpForwardEntry2(&check) != nil || check.InterfaceIndex != p.Index || check.InterfaceLuid != p.LUID || check.Metric != 5000 || check.DestinationPrefix.PrefixLength != 32 || *(*windows.RawSockaddrInet4)(unsafe.Pointer(&check.NextHop)) != *n || *(*windows.RawSockaddrInet4)(unsafe.Pointer(&check.DestinationPrefix.Prefix)) != *a {
			return errors.New("USB_NATIVE_MAC_ROUTE_READBACK_FAILED")
		}
		return nativeMacScope(ctx, p)
	}); err != nil {
		return err
	}
	if err := EnsureMacSessionRulesNative(ctx, p, token, profile, logger); err != nil {
		return err
	}
	if verifyRetainedAddress != nil {
		return verifyRetainedAddress(p)
	}
	return nil
}

// MacAdapterAbsentNative never removes an adapter. Complete installed NET and
// MIB enumeration must both prove the fixed Mac GUID absent. Errors and limits
// remain failures; an old protected journal cannot authorize a new DIF removal.
func MacAdapterAbsentNative() (bool, error) {
	var table *windows.MibIfTable2
	if windows.GetIfTable2Ex(windows.MibIfEntryNormal, &table) != nil || table == nil {
		return false, errors.New("USB_NATIVE_MAC_ABSENCE_QUERY_FAILED")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 65536 {
		return false, errors.New("USB_NATIVE_MAC_ABSENCE_TABLE_LIMIT")
	}
	for _, r := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
		if strings.EqualFold(r.InterfaceGuid.String(), NativeMacGUID) {
			return false, nil
		}
	}
	class, _ := windows.GUIDFromString(hostNetClass)
	set, err := windows.SetupDiGetClassDevsEx(&class, "", 0, 0, 0, "")
	if err != nil {
		return false, errors.New("USB_NATIVE_MAC_ABSENCE_QUERY_FAILED")
	}
	defer set.Close()
	for i := 0; i < 4096; i++ {
		info, err := set.EnumDeviceInfo(i)
		if err == windows.ERROR_NO_MORE_ITEMS {
			return true, nil
		}
		if err != nil {
			return false, errors.New("USB_NATIVE_MAC_ABSENCE_QUERY_FAILED")
		}
		key, err := set.OpenDevRegKey(info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
		if err == windows.ERROR_FILE_NOT_FOUND {
			continue
		}
		if err != nil {
			return false, errors.New("USB_NATIVE_MAC_ABSENCE_BINDING_UNREADABLE")
		}
		guid, found, err := nativeHostRegistryGUID(key)
		windows.RegCloseKey(key)
		if err != nil {
			return false, err
		}
		if found && strings.EqualFold(guid, NativeMacGUID) {
			return false, nil
		}
	}
	return false, errors.New("USB_NATIVE_MAC_ABSENCE_ENUMERATION_LIMIT")
}

// Native recovery of an old journal is deliberately read-only with respect to
// adapter lifecycle. That schema lacks an instance/LUID/removal transaction;
// do not use the token as authority for a new native DIF_REMOVE operation.
func RecoverMacSessionNative(ctx context.Context, guid, token string, logger *log.Logger) error {
	if !strings.EqualFold(guid, NativeMacGUID) || !idPattern.MatchString(token) {
		return errors.New("USB_NATIVE_MAC_RECOVERY_SCOPE_INVALID")
	}
	absent, err := MacAdapterAbsentNative()
	if err != nil {
		return err
	}
	if !absent {
		return errors.New("USB_NATIVE_MAC_STALE_ADAPTER_REQUIRES_OWNERSHIP_MIGRATION")
	}
	if err := CleanupMacSessionNative(ctx, guid, token, logger); err != nil {
		return err
	}
	return VerifyMacCleanupNative(ctx, guid, token, logger)
}

func WaitMacCleanupNative(ctx context.Context, guid, token string, logger *log.Logger) error {
	if !strings.EqualFold(guid, NativeMacGUID) || !idPattern.MatchString(token) {
		return errors.New("USB_NATIVE_SESSION_RULE_SCOPE_INVALID")
	}
	if err := removeNativeSessionRules(ctx, guid, token, true, logger); err != nil {
		return err
	}
	return nativeStep(logger, "mac_adapter_close_settle", func() error {
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		poll := time.NewTicker(100 * time.Millisecond)
		defer poll.Stop()
		for {
			absent, err := MacAdapterAbsentNative()
			if err != nil {
				return err
			}
			if absent {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-deadline.C:
				return errors.New("USB_NATIVE_MAC_CLOSE_ABSENCE_UNCONFIRMED")
			case <-poll.C:
			}
		}
	})
}

// CleanupOwnedMacSessionNative requires the caller's exact protected session
// and actual held adapter lease. Local typed identity remains mandatory even
// after USB detach; this API grants no address, Ready or creation authority.
// The callback must not recursively acquire usbaddress.ConfigurationLock.
func CleanupOwnedMacSessionNative(ctx context.Context, p usbaddress.InterfaceProof, token string, verifyProtectedSession func() error, logger *log.Logger) error {
	if ctx == nil || p.Role != "" || !strings.EqualFold(p.GUID, NativeMacGUID) || p.Index == 0 || p.LUID == 0 || verifyProtectedSession == nil || !idPattern.MatchString(token) {
		return errors.New("USB_NATIVE_SESSION_CLEANUP_OWNER_REQUIRED")
	}
	verify := func() error {
		return VerifyOwnedWintunRecoveryIdentityNative(ctx, OwnedProfileRecoveryIdentity{Role: "mac", GUID: p.GUID, Index: p.Index, LUID: p.LUID}, verifyProtectedSession)
	}
	return removeOwnedNativeSessionRules(ctx, p.GUID, token, false, verify, logger)
}

// CleanupRetainedMacSessionNative removes only this completed session's owned
// token rules and the exact fixed peer route. It preserves address and adapter.
// Caller proves its protected completed retained session before any mutation.
func CleanupRetainedMacSessionNative(ctx context.Context, p usbaddress.InterfaceProof, token string, verifyCompletedSession func() error, logger *log.Logger) error {
	if ctx == nil || p.Index == 0 || p.LUID == 0 || !strings.EqualFold(p.GUID, NativeMacGUID) || verifyCompletedSession == nil || !idPattern.MatchString(token) {
		return errors.New("USB_NATIVE_MAC_RETAINED_OWNER_REQUIRED")
	}
	verify := func() error {
		if e := verifyCompletedSession(); e != nil {
			return e
		}
		return ctx.Err()
	}
	if e := verify(); e != nil {
		return e
	}
	if e := CleanupOwnedMacSessionNative(ctx, p, token, verify, logger); e != nil {
		return e
	}
	if e := verify(); e != nil {
		return e
	}
	row := windows.MibIpForwardRow2{}
	init := macMTUIPHelper.NewProc("InitializeIpForwardEntry")
	if init.Find() != nil {
		return errors.New("USB_NATIVE_NETWORK_API_UNAVAILABLE")
	}
	init.Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceIndex = p.Index
	row.InterfaceLuid = p.LUID
	row.DestinationPrefix.PrefixLength = 32
	row.Metric = 5000
	row.Protocol = 3
	a := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.DestinationPrefix.Prefix))
	a.Family = windows.AF_INET
	a.Addr = [4]byte{10, 6, 9, 2}
	n := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.NextHop))
	n.Family = windows.AF_INET
	got := row
	e := windows.GetIpForwardEntry2(&got)
	if e == windows.ERROR_NOT_FOUND || e == windows.ERROR_FILE_NOT_FOUND {
		return verify()
	}
	if e != nil || got.InterfaceIndex != row.InterfaceIndex || got.InterfaceLuid != row.InterfaceLuid || got.Metric != row.Metric || got.Protocol != row.Protocol || got.DestinationPrefix.PrefixLength != 32 || *(*windows.RawSockaddrInet4)(unsafe.Pointer(&got.NextHop)) != *n || *(*windows.RawSockaddrInet4)(unsafe.Pointer(&got.DestinationPrefix.Prefix)) != *a {
		return errors.New("USB_NATIVE_MAC_RETAINED_ROUTE_CHANGED")
	}
	if e = verify(); e != nil {
		return e
	}
	if e = nativeIPCall("DeleteIpForwardEntry2", unsafe.Pointer(&got)); e != nil {
		return e
	}
	got = row
	e = windows.GetIpForwardEntry2(&got)
	if e != windows.ERROR_NOT_FOUND && e != windows.ERROR_FILE_NOT_FOUND {
		return errors.New("USB_NATIVE_MAC_RETAINED_ROUTE_ABSENCE_UNPROVEN")
	}
	return verify()
}
