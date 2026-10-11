//go:build windows && amd64

// Native layouts follow Microsoft's Windows SDK fwpmtypes.h (x64).
package usbgateway

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"net/netip"
	"runtime"
	"suhang/usbnet/internal/transport/routing"
	"unsafe"
)

type blob struct {
	Size uint32
	Data *byte
}
type value struct {
	Type uint32
	Data uintptr
}
type display struct{ Name, Description *uint16 }
type condition struct {
	Key   windows.GUID
	Match uint32
	Value value
}
type action struct {
	Type uint32
	Key  windows.GUID
}
type filter struct {
	Key             windows.GUID
	Display         display
	Flags           uint32
	Provider        *windows.GUID
	Data            blob
	Layer, Sublayer windows.GUID
	Weight          value
	Count           uint32
	Conditions      *condition
	Action          action
	Padding         [4]byte
	Context         windows.GUID
	Reserved        *windows.GUID
	ID              uint64
	Effective       value
}
type sublayer struct {
	Key      windows.GUID
	Display  display
	Flags    uint32
	Provider *windows.GUID
	Data     blob
	Weight   uint16
}
type subscription struct {
	Template uintptr
	Flags    uint32
	Key      windows.GUID
}
type eventHeader struct {
	Time                  windows.Filetime
	Flags, IPVersion      uint32
	Protocol              byte
	Pad                   [3]byte
	Local, Remote         [16]byte
	LocalPort, RemotePort uint16
	Scope                 uint32
	App                   blob
	User                  uintptr
	Reserved              [56]byte
}
type netEvent struct {
	Header eventHeader
	Type   uint32
	Drop   *classifyDrop
}
type classifyDrop struct {
	FilterID                             uint64
	LayerID                              uint16
	Reason, Original, Current, Direction uint32
	Loopback                             int32
}

var fwpm = windows.NewLazySystemDLL("fwpuclnt.dll")

// Preserve pointers converted to uintptr by callers across lazy DLL lookup,
// stack growth, and GC. KeepAlive alone does not move stack objects to the heap.
//
//go:uintptrescapes
func call(name string, args ...uintptr) error {
	r, _, _ := fwpm.NewProc(name).Call(args...)
	return wfpCallResult(name, uint64(r))
}

func guid(s string) windows.GUID {
	g, e := windows.GUIDFromString(s)
	if e != nil {
		panic(e)
	}
	return g
}

var layers = []windows.GUID{guid("{c38d57d1-05a7-4c33-904f-7fbceee60e82}"), guid("{e1cd9fe7-f4b5-4273-96c0-592e487b8650}"), guid("{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}"), guid("{a3b42c97-9f04-4672-b87e-cee9c483257f}")}
var interfaceKey = guid("{4cd62a49-59c3-4969-b7f3-bda5d32890a4}")
var appKey = guid("{d78e1e87-8644-4ea5-9437-d809ecefc971}")

func randomGUID() (windows.GUID, error) { return windows.GenerateGUID() }
func nativeLayout() error {
	if unsafe.Sizeof(filter{}) != 200 || unsafe.Offsetof(filter{}.Action) != 128 || unsafe.Offsetof(filter{}.ID) != 176 || unsafe.Sizeof(condition{}) != 40 || unsafe.Sizeof(sublayer{}) != 72 || unsafe.Sizeof(eventHeader{}) != 144 || unsafe.Offsetof(netEvent{}.Drop) != 152 || unsafe.Sizeof(classifyDrop{}) != 32 {
		return fmt.Errorf("GATEWAY_NATIVE_ABI_INVALID")
	}
	return nil
}
func openEngine() (uintptr, error) {
	if e := nativeLayout(); e != nil {
		return 0, e
	}
	var handle uintptr
	err := call("FwpmEngineOpen0", 0, 10, 0, 0, uintptr(unsafe.Pointer(&handle)))
	return handle, err
}
func closeEngine(h uintptr) { call("FwpmEngineClose0", h) }
func transaction(h uintptr, f func() error) error {
	if e := call("FwpmTransactionBegin0", h, 0); e != nil {
		return e
	}
	if e := f(); e != nil {
		call("FwpmTransactionAbort0", h)
		return e
	}
	if e := call("FwpmTransactionCommit0", h); e != nil {
		call("FwpmTransactionAbort0", h)
		return e
	}
	return nil
}
func addSublayer(h uintptr, key windows.GUID) error {
	s := sublayer{Key: key, Display: display{windows.StringToUTF16Ptr("USB Link · USB Gateway"), windows.StringToUTF16Ptr("USB Link owns this USB-scoped policy")}, Weight: 0xffff}
	e := call("FwpmSubLayerAdd0", h, uintptr(unsafe.Pointer(&s)), 0)
	runtime.KeepAlive(s)
	return e
}
func addFilter(h uintptr, key, sub windows.GUID, spec Specification) (uint64, error) {
	return filterOperation(h, key, sub, spec, false)
}
func verifyFilter(h uintptr, key, sub windows.GUID, spec Specification) error {
	_, e := filterOperation(h, key, sub, spec, true)
	return e
}

func filterIdentity(h uintptr, id uint64) string {
	var f *filter
	if e := call("FwpmFilterGetById0", h, uintptr(id), uintptr(unsafe.Pointer(&f))); e != nil || f == nil {
		return "readback unavailable"
	}
	defer call("FwpmFreeMemory0", uintptr(unsafe.Pointer(&f)))
	// SDK display strings are terminated native WCHARs. Avoid unbounded reads.
	if f.Display.Name == nil {
		return ""
	}
	p := f.Display.Name
	u := make([]uint16, 0, 128)
	for i := 0; i < 128; i++ {
		v := *(*uint16)(unsafe.Add(unsafe.Pointer(p), i*2))
		if v == 0 {
			break
		}
		u = append(u, v)
	}
	return windows.UTF16ToString(u)
}
func filterOperation(h uintptr, key, sub windows.GUID, spec Specification, verify bool) (uint64, error) {
	layer, luid, path, permit := guid(spec.Layer), spec.LUID, spec.Application, spec.Permit
	var pins runtime.Pinner
	defer pins.Unpin()
	pins.Pin(&luid)
	conditions := []condition{{Key: guid(spec.InterfaceField), Value: value{Type: 4, Data: uintptr(unsafe.Pointer(&luid))}}}
	type v4Mask struct{ Address, Mask uint32 }
	localMask := v4Mask{0x0a060901, 0xffffffff}
	pins.Pin(&localMask)
	remoteMask := v4Mask{0x0a060900, 0xffffff00}
	pins.Pin(&remoteMask)
	if spec.NetworkOnlyBlock {
		if e := validateNetworkOnlySpec(spec); e != nil {
			return 0, e
		}
		if spec.NetworkOnlyPort != 0 {
			portKey := "{c35a604d-d22b-4e1a-91b4-68f674ee674b}"
			if spec.NetworkOnlyLocalPort {
				portKey = "{0c1ba1af-5765-453f-af22-a8f791ac775b}"
			}
			conditions = append(conditions, condition{Key: guid("{3971ef2b-623e-4f9a-8cb1-6e79b806b9a7}"), Value: value{Type: 1, Data: uintptr(spec.NetworkOnlyProtocol)}}, condition{Key: guid(portKey), Value: value{Type: 2, Data: uintptr(spec.NetworkOnlyPort)}})
		}
		if spec.NetworkOnlyPeer != "" {
			remoteMask = v4Mask{0x0a060903, 0xffffffff}
			conditions = append(conditions, condition{Key: guid("{b235ae9a-1d64-49b8-a44c-5ff3d9095045}"), Value: value{Type: 256, Data: uintptr(unsafe.Pointer(&remoteMask))}})
		}
	}
	if spec.NativeSMBPeer != "" {
		if e := validateNativeSMBSpec(spec); e != nil {
			return 0, e
		}
		if spec.NativeSMBPeer == "10.6.9.2" {
			remoteMask.Address = 0x0a060902
		} else {
			remoteMask.Address = 0x0a060903
		}
		remoteMask.Mask = 0xffffffff
		conditions = append(conditions, condition{Key: guid("{d9ee00de-c1ef-4617-bfe3-ffd8f5a08957}"), Value: value{Type: 256, Data: uintptr(unsafe.Pointer(&localMask))}}, condition{Key: guid("{b235ae9a-1d64-49b8-a44c-5ff3d9095045}"), Value: value{Type: 256, Data: uintptr(unsafe.Pointer(&remoteMask))}}, condition{Key: guid("{3971ef2b-623e-4f9a-8cb1-6e79b806b9a7}"), Value: value{Type: 1, Data: 6}}, condition{Key: guid("{0c1ba1af-5765-453f-af22-a8f791ac775b}"), Value: value{Type: 2, Data: 445}})
	}
	if spec.DiagnosticICMP != "" {
		if e := validateDiagnosticICMPSpec(spec); e != nil {
			return 0, e
		}
		remoteMask = v4Mask{0x0a060902, 0xffffffff}
		typ := uintptr(0)
		if spec.DiagnosticICMP == "request" {
			typ = 8
		}
		conditions = append(conditions,
			condition{Key: guid("{d9ee00de-c1ef-4617-bfe3-ffd8f5a08957}"), Value: value{Type: 256, Data: uintptr(unsafe.Pointer(&localMask))}},
			condition{Key: guid("{b235ae9a-1d64-49b8-a44c-5ff3d9095045}"), Value: value{Type: 256, Data: uintptr(unsafe.Pointer(&remoteMask))}},
			condition{Key: guid("{3971ef2b-623e-4f9a-8cb1-6e79b806b9a7}"), Value: value{Type: 1, Data: 1}},
			condition{Key: guid("{0c1ba1af-5765-453f-af22-a8f791ac775b}"), Value: value{Type: 2, Data: typ}},
			condition{Key: guid("{c35a604d-d22b-4e1a-91b4-68f674ee674b}"), Value: value{Type: 2, Data: 0}})
	}
	if spec.HostServiceOnly {
		conditions = append(conditions, condition{Key: guid("{d9ee00de-c1ef-4617-bfe3-ffd8f5a08957}"), Value: value{Type: 256, Data: uintptr(unsafe.Pointer(&localMask))}}, condition{Key: guid("{b235ae9a-1d64-49b8-a44c-5ff3d9095045}"), Value: value{Type: 256, Data: uintptr(unsafe.Pointer(&remoteMask))}})
	}
	sourceMask, destMask := v4Mask{}, v4Mask{}
	pins.Pin(&sourceMask)
	pins.Pin(&destMask)
	other := spec.OtherLUID
	pins.Pin(&other)
	if spec.InternetForward {
		src, se := netip.ParsePrefix(spec.ForwardSource)
		dst, de := netip.ParsePrefix(spec.ForwardDestination)
		peer := netip.MustParsePrefix("10.6.9.2/32")
		public := src
		if src == peer {
			public = dst
		}
		if se != nil || de != nil || spec.OtherLUID == 0 || spec.OtherLUID == spec.LUID || !spec.Permit || spec.Layer != forwardingLayers[0] || (src != peer && dst != peer) || !routing.PublicPrefix(public, nil) {
			return 0, fmt.Errorf("INTERNET_FORWARD_SCOPE_INVALID")
		}
		src4, dst4 := src.Addr().As4(), dst.Addr().As4()
		sourceMask = v4Mask{binary.BigEndian.Uint32(src4[:]), ^uint32(0) << uint(32-src.Bits())}
		destMask = v4Mask{binary.BigEndian.Uint32(dst4[:]), ^uint32(0) << uint(32-dst.Bits())}
		otherField := forwardInterface
		if spec.InterfaceField == forwardInterface {
			otherField = localInterface
		}
		conditions = append(conditions, condition{Key: guid(otherField), Value: value{Type: 4, Data: uintptr(unsafe.Pointer(&other))}})
		conditions = append(conditions, condition{Key: guid("{ae96897e-2e94-4bc9-b313-b27ee80e574d}"), Value: value{Type: 256, Data: uintptr(unsafe.Pointer(&sourceMask))}}, condition{Key: guid("{2d79133b-b390-45c6-8699-acaceaafed33}"), Value: value{Type: 256, Data: uintptr(unsafe.Pointer(&destMask))}})
	} else if spec.ForwardSource != "" || spec.ForwardDestination != "" {
		src, dst, e := exactLocalDeliveryAddresses(spec)
		if e != nil {
			return 0, e
		}
		sourceMask = v4Mask{src, 0xffffffff}
		destMask = v4Mask{dst, 0xffffffff}
		conditions = append(conditions, condition{Key: guid("{ae96897e-2e94-4bc9-b313-b27ee80e574d}"), Value: value{Type: 256, Data: uintptr(unsafe.Pointer(&sourceMask))}}, condition{Key: guid("{2d79133b-b390-45c6-8699-acaceaafed33}"), Value: value{Type: 256, Data: uintptr(unsafe.Pointer(&destMask))}})
	}

	var app *blob
	if path != "" {
		p, e := windows.UTF16PtrFromString(path)
		if e != nil {
			return 0, e
		}
		if e = call("FwpmGetAppIdFromFileName0", uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&app))); e != nil {
			return 0, e
		}
		defer call("FwpmFreeMemory0", uintptr(unsafe.Pointer(&app)))
		conditions = append(conditions, condition{Key: appKey, Value: value{Type: 12, Data: uintptr(unsafe.Pointer(app))}})
	}
	weight := uint64(1)
	pins.Pin(&weight)
	act := uint32(0x1001)
	if permit {
		weight = 100
		act = 0x1002
	}
	if spec.NetworkOnlyBlock {
		weight = 1000
	}
	f := filter{Key: key, Display: display{windows.StringToUTF16Ptr("USB Link Gateway"), windows.StringToUTF16Ptr("USB Link owns this USB-scoped policy")}, Layer: layer, Sublayer: sub, Weight: value{Type: 4, Data: uintptr(unsafe.Pointer(&weight))}, Count: uint32(len(conditions)), Conditions: &conditions[0], Action: action{Type: act}}
	if !verify {
		var id uint64
		e := call("FwpmFilterAdd0", h, uintptr(unsafe.Pointer(&f)), 0, uintptr(unsafe.Pointer(&id)))
		runtime.KeepAlive(luid)
		runtime.KeepAlive(weight)
		runtime.KeepAlive(conditions)
		runtime.KeepAlive(sourceMask)
		runtime.KeepAlive(destMask)
		runtime.KeepAlive(localMask)
		runtime.KeepAlive(remoteMask)
		runtime.KeepAlive(f)
		return id, e
	}
	// Check the exact effective object; a successful RPC alone is not acceptance.
	var actual *filter
	e := call("FwpmFilterGetByKey0", h, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&actual)))
	if e != nil {
		return 0, e
	}
	defer call("FwpmFreeMemory0", uintptr(unsafe.Pointer(&actual)))
	if actual == nil {
		return 0, fmt.Errorf("GATEWAY_FILTER_READBACK_FAILED field=object actual=nil")
	}
	if actual.Key != key {
		return 0, fmt.Errorf("GATEWAY_FILTER_READBACK_FAILED field=key actual=%s expected=%s", actual.Key.String(), key.String())
	}
	if actual.Sublayer != sub {
		return 0, fmt.Errorf("GATEWAY_FILTER_READBACK_FAILED field=sublayer actual=%s expected=%s", actual.Sublayer.String(), sub.String())
	}
	if actual.Layer != layer {
		return 0, fmt.Errorf("GATEWAY_FILTER_READBACK_FAILED field=layer actual=%s expected=%s", actual.Layer.String(), layer.String())
	}
	if spec.NetworkOnlyBlock && (actual.Weight.Type != 4 || actual.Weight.Data == 0 || *(*uint64)(valuePointer(&actual.Weight)) != weight) {
		return 0, fmt.Errorf("GATEWAY_NETWORK_ONLY_WEIGHT_READBACK_FAILED")
	}
	if actual.Action.Type != act {
		return 0, fmt.Errorf("GATEWAY_FILTER_READBACK_FAILED field=action actual=0x%x expected=0x%x", actual.Action.Type, act)
	}
	if e := validateFilterFlags(actual.Flags); e != nil {
		return 0, e
	}
	if actual.Count != uint32(len(conditions)) || actual.Conditions == nil {
		return 0, fmt.Errorf("GATEWAY_FILTER_READBACK_FAILED field=conditions count=%d expected=%d null=%t", actual.Count, len(conditions), actual.Conditions == nil)
	}
	returned := unsafe.Slice(actual.Conditions, int(actual.Count))
	wantFields, gotFields := make([]string, len(conditions)), make([]string, len(returned))
	for i := range conditions {
		wantFields[i] = conditions[i].Key.String()
	}
	for i := range returned {
		gotFields[i] = returned[i].Key.String()
	}
	order, e := conditionOrder(wantFields, gotFields)
	if e != nil {
		return 0, e
	}
	for i := range conditions {
		want, got := conditions[i], returned[order[i]]
		if got.Key != want.Key || got.Match != want.Match || got.Value.Type != want.Value.Type {
			return 0, fmt.Errorf("GATEWAY_CONDITION_READBACK_FAILED index=%d field=%s expected=%s match=%d type=%d expected_type=%d", i, got.Key.String(), want.Key.String(), got.Match, got.Value.Type, want.Value.Type)
		}
		if got.Value.Type == 1 && uint8(got.Value.Data) != uint8(want.Value.Data) || got.Value.Type == 2 && uint16(got.Value.Data) != uint16(want.Value.Data) {
			return 0, fmt.Errorf("GATEWAY_PORT_PROTOCOL_READBACK_FAILED")
		}
		if got.Value.Type == 4 {
			if got.Value.Data == 0 || *(*uint64)(valuePointer(&got.Value)) != *(*uint64)(valuePointer(&want.Value)) {
				return 0, fmt.Errorf("GATEWAY_INTERFACE_READBACK_FAILED")
			}
		}
		if got.Value.Type == 256 {
			if got.Value.Data == 0 || want.Value.Data == 0 || *(*v4Mask)(valuePointer(&got.Value)) != *(*v4Mask)(valuePointer(&want.Value)) {
				return 0, fmt.Errorf("GATEWAY_ADDRESS_SCOPE_READBACK_FAILED")
			}
		}
		if got.Value.Type == 12 {
			actualBlob := (*blob)(valuePointer(&got.Value))
			if actualBlob == nil || actualBlob.Size != app.Size || actualBlob.Data == nil || string(unsafe.Slice(actualBlob.Data, int(actualBlob.Size))) != string(unsafe.Slice(app.Data, int(app.Size))) {
				return 0, fmt.Errorf("GATEWAY_APPLICATION_READBACK_FAILED")
			}
		}
	}
	return actual.ID, nil
}
func removeFilter(h uintptr, key, sub windows.GUID) error {
	var actual *filter
	e := call("FwpmFilterGetByKey0", h, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&actual)))
	if e != nil {
		if isNotFound(e) {
			return nil
		}
		return e
	}
	if actual == nil {
		return fmt.Errorf("GATEWAY_FILTER_READBACK_FAILED")
	}
	owned := actual.Key == key && actual.Sublayer == sub && actual.Display.Description != nil && windows.UTF16PtrToString(actual.Display.Description) == "USB Link owns this USB-scoped policy"
	call("FwpmFreeMemory0", uintptr(unsafe.Pointer(&actual)))
	if !owned {
		return fmt.Errorf("GATEWAY_FILTER_OWNERSHIP_CHANGED")
	}
	return call("FwpmFilterDeleteByKey0", h, uintptr(unsafe.Pointer(&key)))
}

// The compiler checks the x64 ABI even on a non-Windows build host.
var _ [200 - int(unsafe.Sizeof(filter{}))]byte
var _ [int(unsafe.Sizeof(filter{})) - 200]byte
var _ [144 - int(unsafe.Sizeof(eventHeader{}))]byte
var _ [int(unsafe.Sizeof(eventHeader{})) - 144]byte
var _ [152 - int(unsafe.Offsetof(netEvent{}.Drop))]byte
var _ [int(unsafe.Offsetof(netEvent{}.Drop)) - 152]byte

// Decode pointer-valued native unions without treating scalar union bits as Go pointers.
func valuePointer(v *value) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&v.Data)) }
