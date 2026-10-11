//go:build windows && amd64

package netconfig

import (
	"context"
	"errors"
	"log"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/platform/windows/wincom"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These fixed typed slots follow Microsoft's netlistmgr.h. GUID-valued
// INetwork/INetworkConnection methods are not ordinary automation scalars.
const nlmCLSID = "{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"
const nlmIID = "{DCB00000-570F-4A9B-8D69-199FDBA5723B}"

var nlmCreate = windows.NewLazySystemDLL("ole32.dll").NewProc("CoCreateInstance")

func nlmCall(ptr uintptr, slot int, args ...uintptr) uintptr {
	object := *(*unsafe.Pointer)(unsafe.Pointer(&ptr))
	table := *(*unsafe.Pointer)(object)
	method := *(*uintptr)(unsafe.Add(table, slot*int(unsafe.Sizeof(uintptr(0)))))
	args = append([]uintptr{ptr}, args...)
	hr, _, _ := syscall.SyscallN(method, args...)
	return hr
}
func nlmResult(hr uintptr) error {
	if int32(hr) < 0 {
		return &wincom.Error{HRESULT: uint32(hr)}
	}
	return nil
}
func nlmRelease(p uintptr) {
	if p != 0 {
		nlmCall(p, 2)
	}
}
func nlmEnumerate(enum uintptr, fn func(uintptr) error) error {
	if enum == 0 {
		return errors.New("USB_NATIVE_PROFILE_ENUMERATOR_NULL")
	}
	defer nlmRelease(enum)
	for i := 0; i < 1024; i++ {
		var connection uintptr
		var fetched uint32
		hr := nlmCall(enum, 8, 1, uintptr(unsafe.Pointer(&connection)), uintptr(unsafe.Pointer(&fetched)))
		if uint32(hr) == 1 && fetched == 0 && connection == 0 {
			return nil
		}
		if hr != 0 || fetched != 1 || connection == 0 {
			nlmRelease(connection)
			return errors.New("USB_NATIVE_PROFILE_ENUMERATION_FAILED")
		}
		err := fn(connection)
		nlmRelease(connection)
		if err != nil {
			return err
		}
	}
	return errors.New("USB_NATIVE_PROFILE_ENUMERATION_LIMIT")
}
func nlmAdapter(connection uintptr) (windows.GUID, error) {
	var guid windows.GUID
	e := nlmResult(nlmCall(connection, 12, uintptr(unsafe.Pointer(&guid))))
	return guid, e
}
func nlmRead(ctx context.Context, p usbaddress.InterfaceProof) (network uintptr, guid string, category uint32, err error) {
	return nlmReadVerified(ctx, p.GUID, func() error { _, e := nativeRuleInterface(ctx, p); return e })
}

// The verifier is private and repeated around every complete NLM observation.
// Recovery supplies an exact protected-owner/native identity gate, never a
// Role-empty firewall proof or a diagnostic snapshot as authorization.
func nlmReadVerified(ctx context.Context, adapterGUID string, verify func() error) (network uintptr, guid string, category uint32, err error) {
	if err = verify(); err != nil {
		return
	}
	class, _ := windows.GUIDFromString(nlmCLSID)
	iid, _ := windows.GUIDFromString(nlmIID)
	if nlmCreate.Find() != nil {
		return 0, "", 0, errors.New("USB_NATIVE_PROFILE_API_UNAVAILABLE")
	}
	var manager uintptr
	hr, _, _ := nlmCreate.Call(uintptr(unsafe.Pointer(&class)), 0, 5, uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&manager)))
	if err = nlmResult(hr); err != nil {
		return
	}
	if manager == 0 {
		return 0, "", 0, errors.New("USB_NATIVE_PROFILE_MANAGER_NULL")
	}
	defer nlmRelease(manager)
	var enum uintptr
	if err = nlmResult(nlmCall(manager, 9, uintptr(unsafe.Pointer(&enum)))); err != nil {
		return
	}
	count := 0
	err = nlmEnumerate(enum, func(connection uintptr) error {
		adapter, e := nlmAdapter(connection)
		if e != nil {
			return e
		}
		if !strings.EqualFold(adapter.String(), adapterGUID) {
			return nil
		}
		count++
		if count > 1 {
			return errors.New("USB_NATIVE_PROFILE_TARGET_AMBIGUOUS")
		}
		return nlmResult(nlmCall(connection, 7, uintptr(unsafe.Pointer(&network))))
	})
	ownedNetwork := network
	defer func() {
		if err != nil {
			nlmRelease(ownedNetwork)
			network = 0
		}
	}()
	if err != nil {
		return
	}
	if count == 0 {
		return 0, "", 0, verify()
	}
	if network == 0 {
		return 0, "", 0, errors.New("USB_NATIVE_PROFILE_NETWORK_NULL")
	}
	var id windows.GUID
	if err = nlmResult(nlmCall(network, 11, uintptr(unsafe.Pointer(&id)))); err != nil {
		return
	}
	guid = id.String()
	var members uintptr
	if err = nlmResult(nlmCall(network, 13, uintptr(unsafe.Pointer(&members)))); err != nil {
		return
	}
	membersCount := 0
	err = nlmEnumerate(members, func(connection uintptr) error {
		membersCount++
		adapter, e := nlmAdapter(connection)
		if e != nil {
			return e
		}
		if !strings.EqualFold(adapter.String(), adapterGUID) {
			return errors.New("USB_NATIVE_PROFILE_NETWORK_HAS_FOREIGN_INTERFACE")
		}
		return nil
	})
	if err != nil {
		return
	}
	if membersCount != 1 {
		return 0, "", 0, errors.New("USB_NATIVE_PROFILE_NETWORK_MEMBERS_CHANGED")
	}
	if err = nlmResult(nlmCall(network, 18, uintptr(unsafe.Pointer(&category)))); err != nil {
		return
	}
	if category > 1 {
		return 0, "", 0, errors.New("USB_NATIVE_PROFILE_DOMAIN_OR_UNKNOWN")
	}
	err = verify()
	return
}

// ReadPrivateProfileNative returns only the exact exclusive USB network. An
// absent NLA profile returns an empty GUID; interface-scoped firewall rules do
// not need a network category. It never changes a shared or domain network.
func ReadPrivateProfileNative(ctx context.Context, p usbaddress.InterfaceProof, logger *log.Logger) (guid string, category uint32, err error) {
	err = nativeStep(logger, "private_profile_read", func() error {
		return wincom.WithApartment(func() error {
			network, g, c, e := nlmRead(ctx, p)
			defer nlmRelease(network)
			guid, category = g, c
			return e
		})
	})
	return
}
func applyPrivateProfile(ctx context.Context, p usbaddress.InterfaceProof, expectedGUID string, desired uint32, expectedCurrent *uint32, allowAlreadyRestored bool, logger *log.Logger) error {
	return applyPrivateProfileVerified(ctx, p.GUID, func() error { _, e := nativeRuleInterface(ctx, p); return e }, expectedGUID, desired, expectedCurrent, allowAlreadyRestored, logger)
}
func applyPrivateProfileVerified(ctx context.Context, adapterGUID string, verify func() error, expectedGUID string, desired uint32, expectedCurrent *uint32, allowAlreadyRestored bool, logger *log.Logger) error {
	if ctx == nil {
		return errors.New("USB_NATIVE_PROFILE_CONTEXT_REQUIRED")
	}
	release, lockErr := usbaddress.ConfigurationLock(ctx)
	if lockErr != nil {
		return lockErr
	}
	defer release()
	if desired > 1 {
		return errors.New("USB_NATIVE_PROFILE_CATEGORY_INVALID")
	}
	return nativeStep(logger, "private_profile_set", func() error {
		return wincom.WithApartment(func() error {
			network, guid, category, e := nlmReadVerified(ctx, adapterGUID, verify)
			if e != nil {
				return e
			}
			defer nlmRelease(network)
			if expectedGUID != "" && !strings.EqualFold(guid, expectedGUID) {
				return errors.New("USB_NATIVE_PROFILE_NETWORK_CHANGED")
			}
			if guid == "" {
				return nil
			}
			if !nativeCategoryAllows(category, desired, expectedCurrent, allowAlreadyRestored) {
				return errors.New("USB_NATIVE_PROFILE_ORIGINAL_OR_OWNED_CATEGORY_CHANGED")
			}
			// Re-observe the full exclusive membership immediately before setting.
			fresh, fg, fc, e := nlmReadVerified(ctx, adapterGUID, verify)
			nlmRelease(fresh)
			if e != nil {
				return e
			}
			if fg != guid || fc != category {
				return errors.New("USB_NATIVE_PROFILE_NETWORK_CHANGED")
			}
			if category != desired {
				if e = nlmResult(nlmCall(network, 19, uintptr(desired))); e != nil {
					return e
				}
			}
			after, ag, ac, e := nlmReadVerified(ctx, adapterGUID, verify)
			defer nlmRelease(after)
			if e != nil {
				return e
			}
			if ag != guid || ac != desired {
				return errors.New("USB_NATIVE_PROFILE_READBACK_CHANGED")
			}
			return nil
		})
	})
}
func SetPrivateProfileNative(ctx context.Context, p usbaddress.InterfaceProof, logger *log.Logger) error {
	return applyPrivateProfile(ctx, p, "", 1, nil, false, logger)
}

// SetPrivateProfileWithOriginalNative is for a durable original-value receipt.
// A category change after that receipt was captured must not be adopted as our
// own mutation. Recovery of an unknown call outcome remains the caller's fence.
func SetPrivateProfileWithOriginalNative(ctx context.Context, p usbaddress.InterfaceProof, expectedNetworkGUID string, originalCategory uint32, logger *log.Logger) error {
	if !guidPattern.MatchString(expectedNetworkGUID) || originalCategory > 1 {
		return errors.New("USB_NATIVE_PROFILE_ORIGINAL_INVALID")
	}
	return applyPrivateProfile(ctx, p, expectedNetworkGUID, 1, &originalCategory, false, logger)
}
func RestorePrivateProfileNative(ctx context.Context, p usbaddress.InterfaceProof, expectedNetworkGUID string, originalCategory uint32, logger *log.Logger) error {
	if !guidPattern.MatchString(expectedNetworkGUID) || originalCategory > 1 {
		return errors.New("USB_NATIVE_PROFILE_ORIGINAL_INVALID")
	}
	ownedCategory := uint32(1)
	return applyPrivateProfile(ctx, p, expectedNetworkGUID, originalCategory, &ownedCategory, true, logger)
}
func SetPrivateMacProfileNative(ctx context.Context, p usbaddress.InterfaceProof, logger *log.Logger) error {
	if e := nativeMacScope(ctx, p); e != nil {
		return e
	}
	return SetPrivateProfileNative(ctx, p, logger)
}
