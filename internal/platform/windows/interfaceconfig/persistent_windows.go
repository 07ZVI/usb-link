//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"reflect"
	"strings"
	"suhang/usbnet/internal/platform/windows/wincom"
	"time"
)

type persistentPolicy struct {
	Values                   []uint32
	AdvertisedRouterLifetime string
}

// Put_ writes an instance, so every applicable unrelated writable interface
// field is freshly compared before and after the one NlMtu change. Missing
// provider fields are not guessed, and no such snapshot authorizes identity.
func readPersistentPolicy(d *wincom.Dispatch) (p persistentPolicy, e error) {
	for _, f := range []struct {
		name string
		kind uint32
	}{{"Forwarding", 17}, {"Advertising", 17}, {"InterfaceMetric", 19}, {"NeighborUnreachabilityDetection", 17}, {"BaseReachableTime", 19}, {"RetransmitTime", 19}, {"DadTransmits", 19}, {"RouterDiscovery", 17}, {"ManagedAddressConfiguration", 17}, {"OtherStatefulConfiguration", 17}, {"WeakHostSend", 17}, {"WeakHostReceive", 17}, {"IgnoreDefaultRoutes", 17}, {"AdvertiseDefaultRoute", 17}, {"CurrentHopLimit", 19}, {"ForceArpNdWolPattern", 17}, {"DirectedMacWolPattern", 17}, {"EcnMarking", 17}, {"Dhcp", 17}, {"AutomaticMetric", 17}, {"DadRetransmitTime", 19}} {
		v, e := cimUint(d, f.name, f.kind)
		if e != nil {
			return p, e
		}
		p.Values = append(p.Values, v)
	}
	p.AdvertisedRouterLifetime, e = cimDateTime(d, "AdvertisedRouterLifetime")
	return p, e
}
func writePersistentMTU(ctx context.Context, svc *wincom.Dispatch, s Scope, n, expectedBefore uint32, verifyOwner func() error) error {
	if e := fresh(ctx, s, verifyOwner); e != nil {
		return e
	}
	d, currentMTU, e := persistentInterface(svc, s)
	if e != nil {
		return e
	}
	defer d.Close()
	if currentMTU != expectedBefore {
		return errors.New("USB_PERSISTENT_MTU_CHANGED_BEFORE_WRITE")
	}
	before, e := readPersistentPolicy(d)
	if e != nil {
		return e
	}
	if e = fresh(ctx, s, verifyOwner); e != nil {
		return e
	}
	if e = cimPut(d, "NlMtu", 19, wincom.UInt(n)); e != nil {
		return e
	}
	v, e := d.Call("Put_", wincom.Int(1))
	v.Clear()
	if e != nil {
		return e
	}
	if e = fresh(ctx, s, verifyOwner); e != nil {
		return e
	}
	check, mtu, e := persistentInterface(svc, s)
	if e != nil {
		return e
	}
	defer check.Close()
	after, e := readPersistentPolicy(check)
	if e != nil || mtu != n || !reflect.DeepEqual(before, after) {
		return errors.New("USB_PERSISTENT_INTERFACE_POLICY_CHANGED")
	}
	return nil
}

func object(d *wincom.Dispatch, name string, method bool, args ...wincom.Value) (*wincom.Dispatch, error) {
	var v wincom.Value
	var e error
	if method {
		v, e = d.Call(name, args...)
	} else {
		v, e = d.Get(name, args...)
	}
	if e != nil {
		return nil, e
	}
	defer v.Clear()
	return v.Dispatch()
}
func cimProperty(d *wincom.Dispatch, name string, want uint32) (*wincom.Dispatch, error) {
	p, e := object(d, "Properties_", false)
	if e != nil {
		return nil, e
	}
	defer p.Close()
	field, e := object(p, "Item", true, wincom.String(name))
	if e != nil {
		return nil, e
	}
	v, e := field.Get("CIMType")
	if e != nil {
		field.Close()
		return nil, e
	}
	kind, e := v.UInt()
	v.Clear()
	if e != nil || kind != want {
		field.Close()
		return nil, errors.New("USB_PERSISTENT_PROPERTY_TYPE_UNPROVEN")
	}
	return field, nil
}
func cimUint(d *wincom.Dispatch, name string, kind uint32) (uint32, error) {
	p, e := cimProperty(d, name, kind)
	if e != nil {
		return 0, e
	}
	defer p.Close()
	v, e := p.Get("Value")
	if e != nil {
		return 0, e
	}
	defer v.Clear()
	return v.UInt()
}
func cimString(d *wincom.Dispatch, name string) (string, error) {
	p, e := cimProperty(d, name, 8)
	if e != nil {
		return "", e
	}
	defer p.Close()
	v, e := p.Get("Value")
	if e != nil {
		return "", e
	}
	defer v.Clear()
	return v.String()
}
func cimBool(d *wincom.Dispatch, name string) (bool, error) {
	p, e := cimProperty(d, name, 11)
	if e != nil {
		return false, e
	}
	defer p.Close()
	v, e := p.Get("Value")
	if e != nil {
		return false, e
	}
	defer v.Clear()
	return v.Bool()
}
func cimPut(d *wincom.Dispatch, name string, kind uint32, value wincom.Value) error {
	p, e := cimProperty(d, name, kind)
	if e != nil {
		return e
	}
	defer p.Close()
	return p.Put("Value", value)
}
func connectCIM() (*wincom.Dispatch, error) {
	l, e := wincom.Create("{76A64158-CB41-11D1-8B02-00600806D9B6}")
	if e != nil {
		return nil, e
	}
	defer l.Close()
	s, e := object(l, "ConnectServer", true, wincom.String("."), wincom.String(`ROOT\StandardCimv2`))
	if e != nil {
		return nil, e
	}
	security, e := object(s, "Security_", false)
	if e != nil {
		s.Close()
		return nil, e
	}
	defer security.Close()
	if e = security.Put("ImpersonationLevel", wincom.Int(3)); e == nil {
		e = security.Put("AuthenticationLevel", wincom.Int(6))
	}
	if e != nil {
		s.Close()
		return nil, e
	}
	return s, nil
}
func query(s *wincom.Dispatch, wql string, max int, fn func(*wincom.Dispatch) error) error {
	r, e := object(s, "ExecQuery", true, wincom.String(wql), wincom.String("WQL"), wincom.Int(48))
	if e != nil {
		return e
	}
	defer r.Close()
	v, e := r.Get("_NewEnum")
	if e != nil {
		return e
	}
	defer v.Clear()
	return wincom.Enumerate(v, max, func(x wincom.Value) error {
		d, e := x.Dispatch()
		if e != nil {
			return e
		}
		defer d.Close()
		return fn(d)
	})
}
func persistentInterface(svc *wincom.Dispatch, s Scope) (*wincom.Dispatch, uint32, error) {
	var out *wincom.Dispatch
	var mtu uint32
	count := 0
	e := query(svc, fmt.Sprintf("SELECT * FROM MSFT_NetIPInterface WHERE InterfaceIndex=%d AND AddressFamily=2 AND Store=0", s.Index), 2, func(d *wincom.Dispatch) error {
		count++
		i, e := cimUint(d, "InterfaceIndex", 19)
		if e != nil {
			return e
		}
		f, e := cimUint(d, "AddressFamily", 18)
		if e != nil {
			return e
		}
		store, e := cimUint(d, "Store", 17)
		if e != nil {
			return e
		}
		alias, e := cimString(d, "InterfaceAlias")
		if e != nil {
			return e
		}
		if i != s.Index || f != 2 || store != 0 || !nativeAliasMatches(s, alias) {
			return errors.New("USB_PERSISTENT_INTERFACE_SCOPE_CHANGED")
		}
		mtu, e = cimUint(d, "NlMtu", 19)
		if e != nil || mtu < 576 || mtu > 65535 {
			return errors.New("USB_PERSISTENT_MTU_UNPROVEN")
		}
		if count > 1 {
			return errors.New("USB_PERSISTENT_INTERFACE_AMBIGUOUS")
		}
		v := wincom.Object(d)
		out, e = v.Dispatch()
		return e
	})
	if e != nil || count != 1 {
		if out != nil {
			out.Close()
		}
		if e == nil {
			e = errors.New("USB_PERSISTENT_INTERFACE_ABSENT")
		}
		return nil, 0, e
	}
	return out, mtu, nil
}

type persistentAddress struct {
	ValidLifetime, PreferredLifetime         string
	Present                                  bool
	IP                                       string
	Prefix, Type, PrefixOrigin, SuffixOrigin uint32
	Skip                                     bool
}

func persistentAddresses(svc *wincom.Dispatch, s Scope) (persistentAddress, *wincom.Dispatch, error) {
	var a persistentAddress
	var out *wincom.Dispatch
	count := 0
	e := query(svc, fmt.Sprintf("SELECT * FROM MSFT_NetIPAddress WHERE InterfaceIndex=%d AND AddressFamily=2 AND Store=0", s.Index), 2, func(d *wincom.Dispatch) error {
		count++
		if count > 1 {
			return errors.New("USB_PERSISTENT_ADDRESS_AMBIGUOUS")
		}
		i, e := cimUint(d, "InterfaceIndex", 19)
		if e != nil {
			return e
		}
		f, e := cimUint(d, "AddressFamily", 18)
		if e != nil {
			return e
		}
		store, e := cimUint(d, "Store", 17)
		if e != nil {
			return e
		}
		alias, e := cimString(d, "InterfaceAlias")
		if e != nil {
			return e
		}
		if i != s.Index || f != 2 || store != 0 || !nativeAliasMatches(s, alias) {
			return errors.New("USB_PERSISTENT_ADDRESS_SCOPE_CHANGED")
		}
		a.Present = true
		a.IP, e = cimString(d, "IPAddress")
		if e != nil {
			return e
		}
		a.Prefix, e = cimUint(d, "PrefixLength", 17)
		if e != nil {
			return e
		}
		a.Type, e = cimUint(d, "Type", 17)
		if e != nil {
			return e
		}
		a.PrefixOrigin, e = cimUint(d, "PrefixOrigin", 18)
		if e != nil {
			return e
		}
		a.SuffixOrigin, e = cimUint(d, "SuffixOrigin", 18)
		if e != nil {
			return e
		}
		a.Skip, e = cimBool(d, "SkipAsSource")
		if e != nil {
			return e
		}
		a.ValidLifetime, e = cimDateTime(d, "ValidLifetime")
		if e != nil {
			return e
		}
		a.PreferredLifetime, e = cimDateTime(d, "PreferredLifetime")
		if e != nil {
			return e
		}
		v := wincom.Object(d)
		out, e = v.Dispatch()
		return e
	})
	if e != nil {
		if out != nil {
			out.Close()
		}
		return a, nil, e
	}
	return a, out, nil
}
func exactPersistentAddress(s Scope, a persistentAddress) bool {
	return a.Present && a.IP == scopeAddress(s) && a.Prefix == 32 && a.Type == 1 && a.PrefixOrigin == 1 && a.SuffixOrigin == 1 && a.Skip == scopeSkip(s)
}
func cimDateTime(d *wincom.Dispatch, name string) (string, error) {
	p, e := cimProperty(d, name, 101)
	if e != nil {
		return "", e
	}
	defer p.Close()
	v, e := p.Get("Value")
	if e != nil {
		return "", e
	}
	defer v.Clear()
	s, e := v.String()
	if e != nil || s == "" || len(s) > 64 {
		return "", errors.New("USB_PERSISTENT_LIFETIME_UNPROVEN")
	}
	return s, nil
}
func addressMatchesBaseline(s Scope, a persistentAddress, b *addressBaseline) bool {
	return exactPersistentAddress(s, a) && b != nil && a.ValidLifetime == b.ValidLifetime && a.PreferredLifetime == b.PreferredLifetime
}

// ProfileOps wraps the fixed native NLM implementation with the same fresh
// live proof. Its members and paths cannot come from remote parameters.
type ProfileOps struct {
	Read               func(context.Context) (string, uint32, error)
	SetPrivate         func(context.Context) error
	SetPrivateExpected func(context.Context, string, uint32) error
	Restore            func(context.Context, string, uint32) error
}

func createPersistentAddress(svc *wincom.Dispatch, s Scope) error {
	c, e := object(svc, "Get", true, wincom.String("MSFT_NetIPAddress"))
	if e != nil {
		return e
	}
	defer c.Close()
	methods, e := object(c, "Methods_", false)
	if e != nil {
		return e
	}
	defer methods.Close()
	method, e := object(methods, "Item", true, wincom.String("Create"))
	if e != nil {
		return e
	}
	defer method.Close()
	definition, e := object(method, "InParameters", false)
	if e != nil {
		return e
	}
	defer definition.Close()
	in, e := object(definition, "SpawnInstance_", true)
	if e != nil {
		return e
	}
	defer in.Close()
	for _, p := range []struct {
		name  string
		kind  uint32
		value wincom.Value
	}{{"InterfaceIndex", 19, wincom.UInt(s.Index)}, {"IPAddress", 8, wincom.String(scopeAddress(s))}, {"AddressFamily", 18, wincom.UInt(2)}, {"PrefixLength", 17, wincom.UInt(32)}, {"Type", 17, wincom.UInt(1)}, {"PrefixOrigin", 18, wincom.UInt(1)}, {"SuffixOrigin", 18, wincom.UInt(1)}, {"SkipAsSource", 11, wincom.Bool(scopeSkip(s))}, {"PolicyStore", 8, wincom.String("PersistentStore")}, {"PassThru", 11, wincom.Bool(false)}} {
		if e = cimPut(in, p.name, p.kind, p.value); e != nil {
			return e
		}
	}
	out, e := object(c, "ExecMethod_", true, wincom.String("Create"), wincom.Object(in))
	if e != nil {
		return e
	}
	defer out.Close()
	code, e := cimUint(out, "ReturnValue", 19)
	if e != nil || code != 0 {
		return errors.New("USB_PERSISTENT_ADDRESS_CREATE_FAILED")
	}
	return nil
}

// ApplyPersistentHost stores settings only for the fixed owned shared host.
// It does not authorize adoption of an ActiveStore address or replace the
// host's Created timestamp journal. Caller must use a distinct persistent mode.
func ApplyPersistent(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps) (o Observation, e error) {
	start := time.Now()
	o.Kind = "persistent_config"
	defer func() { recordTiming(s.Role, "persistent_apply", start, e, o.Code == "DISABLED") }()
	defer func() {
		o.DurationMS = time.Since(start).Milliseconds()
		if e != nil {
			o.Code = "USB_PERSISTENT_CONFIG_UNVERIFIED"
		}
	}()
	if !persistentEnabled.Load() {
		o.Code = "DISABLED"
		return o, nil
	}
	if validateScope(s) != nil {
		return o, errors.New("USB_PERSISTENT_SCOPE_INVALID")
	}
	if profile.Read == nil || profile.SetPrivateExpected == nil || profile.Restore == nil {
		return o, errors.New("USB_PERSISTENT_PROFILE_UNAVAILABLE")
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
	store, found, e := readConfigReceiptFile(dir)
	if e != nil {
		return o, e
	}
	if !found {
		store = configReceipt{Version: 1}
	}
	if store.RestoreRequested {
		return o, errors.New("USB_PERSISTENT_UNINSTALL_PENDING")
	}
	var owned *persistentOriginal
	for i := range store.Persistent {
		if strings.EqualFold(store.Persistent[i].Scope.GUID, s.GUID) {
			owned = &store.Persistent[i]
		}
	}
	e = wincom.WithApartment(func() error {
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
		if _, e = readPersistentPolicy(iface); e != nil {
			return e
		}
		dhcp, e := cimUint(iface, "Dhcp", 17)
		if e != nil || dhcp != 0 {
			return errors.New("USB_PERSISTENT_DHCP_NOT_DISABLED")
		}
		a, addr, e := persistentAddresses(svc, s)
		if addr != nil {
			defer addr.Close()
		}
		if e != nil {
			return e
		}
		if owned == nil {
			if len(store.Persistent) >= 16 {
				return errors.New("USB_PERSISTENT_RECEIPT_LIMIT")
			}
			if a.Present {
				return errors.New("USB_PERSISTENT_EXISTING_ADDRESS_UNOWNED")
			}
			r := persistentOriginal{Scope: s, OriginalMTU: mtu, DesiredMTU: 1500, AddressAbsent: true, Address: scopeAddress(s), Prefix: 32}
			store.Persistent = append(store.Persistent, r)
			if e = writeConfigReceiptFile(dir, store, found); e != nil {
				return e
			}
			owned = &store.Persistent[len(store.Persistent)-1]
		} else {
			if owned.Scope.Role != s.Role || (s.Role != "host" && !persistentScopeMatches(dir, *owned, s)) || !owned.AddressAbsent || (mtu != owned.OriginalMTU && mtu != owned.DesiredMTU) || (a.Present && !addressMatchesBaseline(s, a, owned.AppliedAddress)) {
				return errors.New("USB_PERSISTENT_EXTERNAL_CHANGE")
			}
		}
		if e = fresh(ctx, s, verifyOwner); e != nil {
			return e
		}
		if mtu != 1500 {
			if e = writePersistentMTU(ctx, svc, s, 1500, mtu, verifyOwner); e != nil {
				return e
			}
			o.Applied = true
		}
		if !a.Present {
			if owned.AppliedAddress != nil {
				return errors.New("USB_PERSISTENT_OWNED_ADDRESS_DISAPPEARED")
			}
			if e = fresh(ctx, s, verifyOwner); e != nil {
				return e
			}
			checkAddress, checkObject, e := persistentAddresses(svc, s)
			if checkObject != nil {
				checkObject.Close()
			}
			if e != nil || checkAddress.Present {
				return errors.New("USB_PERSISTENT_ADDRESS_CHANGED_BEFORE_CREATE")
			}
			if e = createPersistentAddress(svc, s); e != nil {
				return e
			}
			o.Applied = true
		}
		if e = fresh(ctx, s, verifyOwner); e != nil {
			return e
		}
		check, newMTU, e := persistentInterface(svc, s)
		if check != nil {
			check.Close()
		}
		if e != nil || newMTU != 1500 {
			return errors.New("USB_PERSISTENT_MTU_READBACK_CHANGED")
		}
		newAddr, check, e := persistentAddresses(svc, s)
		if check != nil {
			check.Close()
		}
		if e != nil || !exactPersistentAddress(s, newAddr) {
			return errors.New("USB_PERSISTENT_ADDRESS_READBACK_CHANGED")
		}
		if owned.AppliedAddress == nil {
			owned.AppliedAddress = &addressBaseline{ValidLifetime: newAddr.ValidLifetime, PreferredLifetime: newAddr.PreferredLifetime}
			if e = writeConfigReceiptFile(dir, store, true); e != nil {
				return e
			}
		} else if !addressMatchesBaseline(s, newAddr, owned.AppliedAddress) {
			return errors.New("USB_PERSISTENT_ADDRESS_READBACK_CHANGED")
		}
		network, category, e := profile.Read(ctx)
		if e != nil {
			return e
		}
		if !guidPattern.MatchString(network) || category > 1 {
			return errors.New("USB_PERSISTENT_PROFILE_UNPROVEN")
		}
		if owned.Profile == nil {
			owned.Profile = &profileOriginal{NetworkGUID: network, Category: int32(category)}
			if e = writeConfigReceiptFile(dir, store, true); e != nil {
				return e
			}
		} else if !strings.EqualFold(owned.Profile.NetworkGUID, network) || (category != 1 && category != uint32(owned.Profile.Category)) {
			return errors.New("USB_PERSISTENT_PROFILE_CHANGED")
		}
		if e = fresh(ctx, s, verifyOwner); e != nil {
			return e
		}
		if category != 1 {
			if e = profile.SetPrivateExpected(ctx, owned.Profile.NetworkGUID, uint32(owned.Profile.Category)); e != nil {
				return e
			}
			o.Applied = true
		}
		network, category, e = profile.Read(ctx)
		if e != nil || !strings.EqualFold(network, owned.Profile.NetworkGUID) || category != 1 {
			return errors.New("USB_PERSISTENT_PROFILE_READBACK_CHANGED")
		}
		return fresh(ctx, s, verifyOwner)
	})
	if e == nil {
		o.Code = "OK"
		o.Verified = true
	}
	return o, e
}

// RestorePersistentHost restores only recorded properties and absence. A
// foreign persistent address/MTU prevents changes and retains the obligation.
func RestorePersistent(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps) (result error) {
	start := time.Now()
	defer func() { recordTiming(s.Role, "persistent_restore", start, result, false) }()
	if validateScope(s) != nil {
		return errors.New("USB_PERSISTENT_SCOPE_INVALID")
	}
	finish, lockErr := lockConfig()
	if lockErr != nil {
		e := lockErr
		return e
	}
	defer finish()
	return restorePersistentUnlocked(ctx, dir, s, verifyOwner, profile, nil)
}

// Caller holds configMutex. A restoring factory may supply an additional
// protected original-to-actual-returned mapping proof; ordinary Apply/active
// proof never receives this capability.
func restorePersistentUnlocked(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps, restoringMapping func(persistentOriginal) bool) error {
	if e := fresh(ctx, s, verifyOwner); e != nil {
		return e
	}
	store, found, e := readConfigReceiptFile(dir)
	if e != nil || !found {
		return e
	}
	which := -1
	var original persistentOriginal
	for i, r := range store.Persistent {
		if strings.EqualFold(r.Scope.GUID, s.GUID) {
			which = i
			original = r
		}
	}
	if which < 0 {
		return nil
	}
	mappingMatches := s.Role == "host" || persistentScopeMatches(dir, original, s)
	if restoringMapping != nil {
		mappingMatches = store.RestoreRequested && restoringMapping(original)
	}
	if original.Scope.Role != s.Role || !mappingMatches {
		return errors.New("USB_PERSISTENT_SCOPE_CHANGED")
	}
	e = wincom.WithApartment(func() error {
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
		if _, e = readPersistentPolicy(iface); e != nil {
			return e
		}
		a, addr, e := persistentAddresses(svc, s)
		if addr != nil {
			defer addr.Close()
		}
		if e != nil {
			return e
		}
		if (mtu != original.OriginalMTU && mtu != 1500) || (a.Present && !addressMatchesBaseline(s, a, original.AppliedAddress)) {
			return errors.New("USB_PERSISTENT_EXTERNAL_CHANGE")
		}
		if original.Profile != nil {
			if profile.Read == nil || profile.Restore == nil {
				return errors.New("USB_PERSISTENT_PROFILE_UNAVAILABLE")
			}
			network, category, e := profile.Read(ctx)
			if e != nil || !strings.EqualFold(network, original.Profile.NetworkGUID) || (category != 1 && category != uint32(original.Profile.Category)) {
				return errors.New("USB_PERSISTENT_PROFILE_RESTORE_UNPROVEN")
			}
			if category != uint32(original.Profile.Category) {
				if e = fresh(ctx, s, verifyOwner); e != nil {
					return e
				}
				if e = profile.Restore(ctx, original.Profile.NetworkGUID, uint32(original.Profile.Category)); e != nil {
					return e
				}
			}
			network, category, e = profile.Read(ctx)
			if e != nil || !strings.EqualFold(network, original.Profile.NetworkGUID) || category != uint32(original.Profile.Category) {
				return errors.New("USB_PERSISTENT_PROFILE_RESTORE_UNVERIFIED")
			}
		}
		if e = fresh(ctx, s, verifyOwner); e != nil {
			return e
		}
		if a.Present {
			checkAddress, checkObject, e := persistentAddresses(svc, s)
			if e != nil {
				return e
			}
			if checkObject == nil || !addressMatchesBaseline(s, checkAddress, original.AppliedAddress) {
				if checkObject != nil {
					checkObject.Close()
				}
				return errors.New("USB_PERSISTENT_ADDRESS_CHANGED_BEFORE_DELETE")
			}
			defer checkObject.Close()
			v, e := checkObject.Call("Delete_", wincom.Int(0))
			v.Clear()
			if e != nil {
				return e
			}
		}
		if mtu != original.OriginalMTU {
			if e = fresh(ctx, s, verifyOwner); e != nil {
				return e
			}
			if e = writePersistentMTU(ctx, svc, s, original.OriginalMTU, mtu, verifyOwner); e != nil {
				return e
			}
		}
		if e = fresh(ctx, s, verifyOwner); e != nil {
			return e
		}
		check, n, e := persistentInterface(svc, s)
		if check != nil {
			check.Close()
		}
		if e != nil || n != original.OriginalMTU {
			return errors.New("USB_PERSISTENT_MTU_RESTORE_UNVERIFIED")
		}
		a, check, e = persistentAddresses(svc, s)
		if check != nil {
			check.Close()
		}
		if e != nil || a.Present {
			return errors.New("USB_PERSISTENT_ADDRESS_RESTORE_UNVERIFIED")
		}
		return fresh(ctx, s, verifyOwner)
	})
	if e != nil {
		return e
	}
	store.Persistent = append(store.Persistent[:which], store.Persistent[which+1:]...)
	return writeConfigReceiptFile(dir, store, true)
}

func nativeAliasMatches(s Scope, alias string) bool {
	r := windows.MibIfRow2{InterfaceLuid: s.LUID}
	return alias != "" && windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &r) == nil && r.InterfaceIndex == s.Index && strings.EqualFold(r.InterfaceGuid.String(), s.GUID) && windows.UTF16ToString(r.Alias[:]) == alias
}
func PersistentEnabled() bool { return persistentEnabled.Load() }
func ApplyPersistentHost(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps) (Observation, error) {
	if s.Role != "host" {
		return Observation{}, errors.New("USB_PERSISTENT_HOST_SCOPE_REQUIRED")
	}
	return ApplyPersistent(ctx, dir, s, verifyOwner, profile)
}
func RestorePersistentHost(ctx context.Context, dir string, s Scope, verifyOwner func() error, profile ProfileOps) error {
	if s.Role != "host" {
		return errors.New("USB_PERSISTENT_HOST_SCOPE_REQUIRED")
	}
	return RestorePersistent(ctx, dir, s, verifyOwner, profile)
}
