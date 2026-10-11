//go:build windows && amd64

// Package wincom is a small, local-only OleAutomation boundary. Callers choose
// fixed CLSIDs and members; no remote input is passed to Create or Invoke.
package wincom

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

type Error struct{ HRESULT uint32 }

func (e *Error) Error() string { return fmt.Sprintf("COM_HRESULT_%08X", e.HRESULT) }

// NativeHRESULT exposes only the typed numeric status, never COM descriptions.
func (e *Error) NativeHRESULT() uint32 {
	if e == nil {
		return 0
	}
	return e.HRESULT
}
func check(hr uintptr) error {
	if int32(hr) < 0 {
		return &Error{uint32(hr)}
	}
	return nil
}

var ole32 = windows.NewLazySystemDLL("ole32.dll")
var oleaut = windows.NewLazySystemDLL("oleaut32.dll")
var initCOM = ole32.NewProc("CoInitializeEx")
var uninitCOM = ole32.NewProc("CoUninitialize")
var createCOM = ole32.NewProc("CoCreateInstance")
var allocString = oleaut.NewProc("SysAllocStringLen")
var freeString = oleaut.NewProc("SysFreeString")
var stringLen = oleaut.NewProc("SysStringLen")
var clearVariant = oleaut.NewProc("VariantClear")
var arrayCreate = oleaut.NewProc("SafeArrayCreateVector")
var arrayPut = oleaut.NewProc("SafeArrayPutElement")
var arrayGet = oleaut.NewProc("SafeArrayGetElement")
var arrayDim = oleaut.NewProc("SafeArrayGetDim")
var arrayLower = oleaut.NewProc("SafeArrayGetLBound")
var arrayUpper = oleaut.NewProc("SafeArrayGetUBound")
var arrayType = oleaut.NewProc("SafeArrayGetVartype")

func WithApartment(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hr, _, _ := initCOM.Call(0, 2)
	if e := check(hr); e != nil {
		return e
	}
	defer uninitCOM.Call()
	return fn()
}

type Dispatch struct{ ptr uintptr }

func (d *Dispatch) Close() {
	if d != nil && d.ptr != 0 {
		call(d.ptr, 2)
		d.ptr = 0
	}
}

// call accepts Go buffers converted to uintptr at its call site. Its own
// annotation is required: SyscallN's annotation does not propagate through a
// Go wrapper, which may allocate or grow the stack before entering the syscall.
//
//go:uintptrescapes
func call(p uintptr, slot int, args ...uintptr) uintptr {
	// These addresses are OleAutomation-owned unmanaged memory, not Go
	// allocations. Decode the native pointer representation without a Go
	// uintptr round trip; retain their lifetime with COM references.
	object := *(*unsafe.Pointer)(unsafe.Pointer(&p))
	v := *(*unsafe.Pointer)(object)
	f := *(*uintptr)(unsafe.Add(v, slot*int(unsafe.Sizeof(uintptr(0)))))
	a := append([]uintptr{p}, args...)
	r, _, _ := syscall.SyscallN(f, a...)
	return r
}
func Create(clsid string) (*Dispatch, error) {
	c, e := windows.GUIDFromString(clsid)
	if e != nil {
		return nil, errors.New("COM_CLASS_INVALID")
	}
	iid, _ := windows.GUIDFromString("{00020400-0000-0000-C000-000000000046}")
	var p uintptr
	hr, _, _ := createCOM.Call(uintptr(unsafe.Pointer(&c)), 0, 5, uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&p)))
	if e = check(hr); e != nil {
		return nil, e
	}
	if p == 0 {
		return nil, errors.New("COM_NULL_DISPATCH")
	}
	return &Dispatch{p}, nil
}

// VARIANT has a 16-byte union on amd64 (BRECORD contains two pointers).
type rawVariant struct {
	VT         uint16
	R1, R2, R3 uint16
	Data       uint64
	Tail       uint64
}
type Value struct {
	raw     rawVariant
	text    *string
	strings []string
	owned   bool
}

func (v Value) IsNull() bool  { return v.text == nil && v.strings == nil && v.raw.VT == 1 }
func (v Value) IsEmpty() bool { return v.text == nil && v.strings == nil && v.raw.VT == 0 }

func String(s string) Value { return Value{text: &s} }
func Int(n int32) Value     { return Value{raw: rawVariant{VT: 3, Data: uint64(uint32(n))}} }
func UInt(n uint32) Value   { return Value{raw: rawVariant{VT: 19, Data: uint64(n)}} }
func Bool(b bool) Value {
	n := uint64(0)
	if b {
		n = 0xffff
	}
	return Value{raw: rawVariant{VT: 11, Data: n}}
}
func Empty() Value { return Value{} }
func Null() Value  { return Value{raw: rawVariant{VT: 1}} }
func Object(d *Dispatch) Value {
	if d == nil {
		return Null()
	}
	return Value{raw: rawVariant{VT: 9, Data: uint64(d.ptr)}}
}
func ArrayStrings(s []string) Value {
	return Value{strings: append([]string{}, s...), raw: rawVariant{VT: 0x2008}}
}
func (v *Value) Clear() {
	if v != nil && v.owned {
		clearVariant.Call(uintptr(unsafe.Pointer(&v.raw)))
		v.owned = false
		v.raw = rawVariant{}
	}
}
func bstr(s string) (uintptr, error) {
	u := utf16.Encode([]rune(s))
	if len(u) > 1<<20 {
		return 0, errors.New("COM_STRING_LIMIT")
	}
	var r uintptr
	if len(u) > 0 {
		r, _, _ = allocString.Call(uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)))
	} else {
		r, _, _ = allocString.Call(0, 0)
	}
	runtime.KeepAlive(u)
	if r == 0 && len(u) > 0 {
		return 0, errors.New("COM_ALLOC_FAILED")
	}
	return r, nil
}
func (v Value) native() (rawVariant, func(), error) {
	if v.text != nil {
		p, e := bstr(*v.text)
		return rawVariant{VT: 8, Data: uint64(p)}, func() { freeString.Call(p) }, e
	}
	if v.strings != nil {
		if len(v.strings) > 4096 {
			return rawVariant{}, nil, errors.New("COM_ARRAY_LIMIT")
		}
		p, _, _ := arrayCreate.Call(8, 0, uintptr(len(v.strings)))
		if p == 0 {
			return rawVariant{}, nil, errors.New("COM_ARRAY_ALLOC_FAILED")
		}
		r := rawVariant{VT: 0x2008, Data: uint64(p)}
		cleanup := func() { clearVariant.Call(uintptr(unsafe.Pointer(&r))) }
		for i, s := range v.strings {
			b, e := bstr(s)
			if e != nil {
				cleanup()
				return rawVariant{}, nil, e
			}
			idx := int32(i)
			hr, _, _ := arrayPut.Call(p, uintptr(unsafe.Pointer(&idx)), b)
			freeString.Call(b)
			if e = check(hr); e != nil {
				cleanup()
				return rawVariant{}, nil, e
			}
		}
		return r, cleanup, nil
	}
	return v.raw, func() {}, nil
}
func (v Value) String() (string, error) {
	if v.text != nil {
		return *v.text, nil
	}
	if v.raw.VT != 8 {
		return "", errors.New("COM_TYPE_STRING")
	}
	p := uintptr(v.raw.Data)
	if p == 0 {
		return "", nil
	}
	n, _, _ := stringLen.Call(p)
	if n > 1<<20 {
		return "", errors.New("COM_STRING_LIMIT")
	}
	characters := *(**uint16)(unsafe.Pointer(&v.raw.Data))
	return string(utf16.Decode(unsafe.Slice(characters, int(n)))), nil
}
func (v Value) Int() (int32, error) {
	switch v.raw.VT {
	case 2:
		return int32(int16(v.raw.Data)), nil
	case 3, 22:
		return int32(v.raw.Data), nil
	case 17, 18, 19, 23:
		if v.raw.Data <= 0x7fffffff {
			return int32(v.raw.Data), nil
		}
	}
	return 0, errors.New("COM_TYPE_INT")
}
func (v Value) UInt() (uint32, error) {
	switch v.raw.VT {
	case 17, 18, 19, 23:
		return uint32(v.raw.Data), nil
	case 2, 3, 22:
		n, e := v.Int()
		if e == nil && n >= 0 {
			return uint32(n), nil
		}
	}
	return 0, errors.New("COM_TYPE_UINT")
}
func (v Value) Bool() (bool, error) {
	if v.raw.VT != 11 || (uint16(v.raw.Data) != 0 && uint16(v.raw.Data) != 0xffff) {
		return false, errors.New("COM_TYPE_BOOL")
	}
	return uint16(v.raw.Data) == 0xffff, nil
}
func (v Value) Dispatch() (*Dispatch, error) {
	if v.raw.VT != 9 || v.raw.Data == 0 {
		return nil, errors.New("COM_TYPE_DISPATCH")
	}
	p := uintptr(v.raw.Data)
	call(p, 1)
	return &Dispatch{p}, nil
}

// Values returns separately owned copies; callers must Clear every element.
func (v Value) Values(max int) (out []Value, err error) {
	if v.strings != nil {
		if max < 0 || max > 4096 || len(v.strings) > max {
			return nil, errors.New("COM_ARRAY_LIMIT")
		}
		for _, s := range v.strings {
			out = append(out, String(s))
		}
		return out, nil
	}
	p := uintptr(v.raw.Data)
	if max < 0 || max > 4096 || v.raw.VT&0x2000 == 0 || v.raw.VT&0x4000 != 0 || p == 0 {
		return nil, errors.New("COM_TYPE_ARRAY")
	}
	dim, _, _ := arrayDim.Call(p)
	if dim != 1 {
		return nil, errors.New("COM_ARRAY_DIMENSION")
	}
	var lo, hi int32
	hr, _, _ := arrayLower.Call(p, 1, uintptr(unsafe.Pointer(&lo)))
	if e := check(hr); e != nil {
		return nil, e
	}
	hr, _, _ = arrayUpper.Call(p, 1, uintptr(unsafe.Pointer(&hi)))
	if e := check(hr); e != nil {
		return nil, e
	}
	if int64(hi)-int64(lo)+1 < 0 || int64(hi)-int64(lo)+1 > int64(max) {
		return nil, errors.New("COM_ARRAY_LIMIT")
	}
	var vt uint16
	hr, _, _ = arrayType.Call(p, uintptr(unsafe.Pointer(&vt)))
	if e := check(hr); e != nil {
		return nil, e
	}
	switch vt {
	case 2, 3, 8, 11, 12, 18, 19:
	default:
		return nil, errors.New("COM_ARRAY_TYPE")
	}
	defer func() {
		if err != nil {
			for i := range out {
				out[i].Clear()
			}
			out = nil
		}
	}()
	for j := int64(lo); j <= int64(hi); j++ {
		i := int32(j)
		r := rawVariant{VT: vt}
		if vt == 12 {
			hr, _, _ = arrayGet.Call(p, uintptr(unsafe.Pointer(&i)), uintptr(unsafe.Pointer(&r)))
		} else {
			hr, _, _ = arrayGet.Call(p, uintptr(unsafe.Pointer(&i)), uintptr(unsafe.Pointer(&r.Data)))
		}
		if e := check(hr); e != nil {
			return out, e
		}
		out = append(out, Value{raw: r, owned: true})
	}
	return out, nil
}
func (v Value) Strings(max int) ([]string, error) {
	if v.strings != nil {
		if max < 0 || max > 4096 || len(v.strings) > max {
			return nil, errors.New("COM_ARRAY_LIMIT")
		}
		return append([]string{}, v.strings...), nil
	}
	p := uintptr(v.raw.Data)
	if max < 0 || max > 4096 || (v.raw.VT != 0x2008 && v.raw.VT != 0x200c) || p == 0 {
		return nil, errors.New("COM_TYPE_STRING_ARRAY")
	}
	dim, _, _ := arrayDim.Call(p)
	if dim != 1 {
		return nil, errors.New("COM_ARRAY_DIMENSION")
	}
	var lo, hi int32
	hr, _, _ := arrayLower.Call(p, 1, uintptr(unsafe.Pointer(&lo)))
	if e := check(hr); e != nil {
		return nil, e
	}
	hr, _, _ = arrayUpper.Call(p, 1, uintptr(unsafe.Pointer(&hi)))
	if e := check(hr); e != nil {
		return nil, e
	}
	if int64(hi)-int64(lo)+1 > int64(max) {
		return nil, errors.New("COM_ARRAY_LIMIT")
	}
	var vt uint16
	hr, _, _ = arrayType.Call(p, uintptr(unsafe.Pointer(&vt)))
	if e := check(hr); e != nil {
		return nil, e
	}
	if vt != 8 && vt != 12 {
		return nil, errors.New("COM_TYPE_STRING_ARRAY")
	}
	out := []string{}
	for j := int64(lo); j <= int64(hi); j++ {
		i := int32(j)
		r := rawVariant{VT: 8}
		if vt == 8 {
			hr, _, _ = arrayGet.Call(p, uintptr(unsafe.Pointer(&i)), uintptr(unsafe.Pointer(&r.Data)))
		} else {
			hr, _, _ = arrayGet.Call(p, uintptr(unsafe.Pointer(&i)), uintptr(unsafe.Pointer(&r)))
		}
		if e := check(hr); e != nil {
			return nil, e
		}
		x := Value{raw: r, owned: true}
		s, e := x.String()
		x.Clear()
		if e != nil {
			return nil, e
		}
		out = append(out, s)
	}
	return out, nil
}

type dispatchParams struct {
	Args              *rawVariant
	Named             *int32
	Count, NamedCount uint32
}
type exceptionInfo struct {
	Code, Reserved                uint16
	Source, Description, HelpFile uintptr
	HelpContext                   uint32
	ReservedPtr, Deferred         uintptr
	SCode                         int32
}

func (d *Dispatch) Get(n string, a ...Value) (Value, error)  { return d.invoke(n, 2, a) }
func (d *Dispatch) Call(n string, a ...Value) (Value, error) { return d.invoke(n, 1, a) }
func (d *Dispatch) Put(n string, v Value) error {
	r, e := d.invoke(n, 4, []Value{v})
	r.Clear()
	return e
}
func (d *Dispatch) invoke(n string, flags uint16, a []Value) (Value, error) {
	if d == nil || d.ptr == 0 || len(a) > 64 || n == "" || len(n) > 128 {
		return Value{}, errors.New("COM_INVOKE_INVALID")
	}
	w, e := windows.UTF16PtrFromString(n)
	if e != nil {
		return Value{}, errors.New("COM_MEMBER_INVALID")
	}
	// Keep the pointer-to-name typed so the GC can also see its pointee.
	names := w
	var zero windows.GUID
	var id int32
	hr := call(d.ptr, 5, uintptr(unsafe.Pointer(&zero)), uintptr(unsafe.Pointer(&names)), 1, 0x400, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(w)
	if e = check(hr); e != nil {
		return Value{}, e
	}
	args := make([]rawVariant, len(a))
	cleanups := []func(){}
	defer func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}()
	for i, v := range a {
		r, c, e := v.native()
		if e != nil {
			return Value{}, e
		}
		args[len(a)-1-i] = r
		cleanups = append(cleanups, c)
	}
	p := dispatchParams{Count: uint32(len(args))}
	if len(args) > 0 {
		p.Args = &args[0]
	}
	putID := int32(-3)
	if flags == 4 {
		p.Named = &putID
		p.NamedCount = 1
	}
	var r rawVariant
	var ex exceptionInfo
	var argErr uint32
	hr = call(d.ptr, 6, uintptr(uint32(id)), uintptr(unsafe.Pointer(&zero)), 0x400, uintptr(flags), uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&r)), uintptr(unsafe.Pointer(&ex)), uintptr(unsafe.Pointer(&argErr)))
	runtime.KeepAlive(args)
	runtime.KeepAlive(w)
	if ex.Deferred != 0 {
		syscall.SyscallN(ex.Deferred, uintptr(unsafe.Pointer(&ex)))
	}
	freeString.Call(ex.Source)
	freeString.Call(ex.Description)
	freeString.Call(ex.HelpFile)
	out := Value{raw: r, owned: true}
	if e = check(hr); e != nil {
		out.Clear()
		if hr == 0x80020009 && ex.SCode < 0 {
			return Value{}, &Error{uint32(ex.SCode)}
		}
		return Value{}, e
	}
	return out, nil
}

// Enumerate bounds the count and clears each callback value before Next. The
// callback may retain an extracted Dispatch (AddRef) but not the Value itself.
func Enumerate(v Value, max int, fn func(Value) error) error {
	if fn == nil || max < 0 || max > 65536 || (v.raw.VT != 13 && v.raw.VT != 9) || v.raw.Data == 0 {
		return errors.New("COM_ENUM_INVALID")
	}
	iid, _ := windows.GUIDFromString("{00020404-0000-0000-C000-000000000046}")
	var p uintptr
	hr := call(uintptr(v.raw.Data), 0, uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&p)))
	if e := check(hr); e != nil {
		return e
	}
	if p == 0 {
		return errors.New("COM_ENUM_NULL")
	}
	defer call(p, 2)
	for i := 0; i <= max; i++ {
		var r rawVariant
		var fetched uint32
		hr = call(p, 3, 1, uintptr(unsafe.Pointer(&r)), uintptr(unsafe.Pointer(&fetched)))
		x := Value{raw: r, owned: true}
		if e := check(hr); e != nil {
			x.Clear()
			return e
		}
		if fetched == 0 {
			x.Clear()
			if hr != 1 {
				return errors.New("COM_ENUM_PROTOCOL")
			}
			return nil
		}
		if fetched != 1 || i == max {
			x.Clear()
			return errors.New("COM_ENUM_LIMIT")
		}
		e := fn(x)
		x.Clear()
		if e != nil {
			return e
		}
	}
	return errors.New("COM_ENUM_LIMIT")
}
