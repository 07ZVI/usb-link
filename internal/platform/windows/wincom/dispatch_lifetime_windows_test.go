//go:build windows && amd64

package wincom

import (
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These callbacks only read the fake object's requests and write ABI output
// buffers. They do not instantiate or mutate any system COM object.
func lifetimeGetIDs(_ uintptr, iid, names, count, locale, id uintptr) uintptr {
	runtime.GC()
	if growLifetimeStack(8) == 0 || count != 1 || locale != 0x400 {
		return 0x80020003
	}
	if *(*windows.GUID)(lifetimePointer(iid)) != (windows.GUID{}) {
		return 0x80020003
	}
	w := *(**uint16)(lifetimePointer(names))
	if windows.UTF16PtrToString(w) != "ReadOnly" {
		return 0x80020003
	}
	*(*int32)(lifetimePointer(id)) = 71
	return 0
}

func lifetimeInvoke(_ uintptr, id, iid, locale, flags, params, result, exception, argErr uintptr) uintptr {
	runtime.GC()
	if growLifetimeStack(8) == 0 || id != 71 || locale != 0x400 || flags != 2 {
		return 0x80020003
	}
	if *(*windows.GUID)(lifetimePointer(iid)) != (windows.GUID{}) {
		return 0x80020003
	}
	p := (*dispatchParams)(lifetimePointer(params))
	if p.Count != 2 || p.NamedCount != 0 || p.Named != nil || p.Args == nil {
		return 0x80020003
	}
	a := unsafe.Slice(p.Args, 2)
	// IDispatch takes arguments in reverse order.
	if a[0].VT != 3 || a[0].Data != 22 || a[1].VT != 3 || a[1].Data != 11 {
		return 0x80020003
	}
	*(*rawVariant)(lifetimePointer(result)) = rawVariant{VT: 3, Data: 42}
	*(*exceptionInfo)(lifetimePointer(exception)) = exceptionInfo{}
	*(*uint32)(lifetimePointer(argErr)) = 0
	return 0
}

func lifetimePointer(p uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}

//go:noinline
func growLifetimeStack(n int) int {
	var page [4096]byte
	page[n] = byte(n + 1)
	if n == 0 {
		return int(page[0])
	}
	return growLifetimeStack(n-1) + int(page[n])
}

func TestReadOnlyDispatchBuffersSurviveGCAndCallbackStackGrowth(t *testing.T) {
	alloc := windows.NewLazySystemDLL("kernel32.dll").NewProc("LocalAlloc")
	block, _, e := alloc.Call(0, 8*unsafe.Sizeof(uintptr(0)))
	if block == 0 {
		t.Fatal(e)
	}
	defer windows.LocalFree(windows.Handle(block))
	words := unsafe.Slice((*uintptr)(lifetimePointer(block)), 8)
	// An unmanaged object followed by a seven-slot fake IDispatch vtable.
	words[0] = block + unsafe.Sizeof(uintptr(0))
	words[6] = syscall.NewCallback(lifetimeGetIDs)
	words[7] = syscall.NewCallback(lifetimeInvoke)
	d := &Dispatch{ptr: block}
	for i := 0; i < 32; i++ {
		v, e := d.Get("ReadOnly", Int(11), Int(22))
		if e != nil {
			t.Fatal(e)
		}
		n, e := v.Int()
		v.Clear()
		if e != nil || n != 42 {
			t.Fatalf("output buffer: %d %v", n, e)
		}
	}
}

func TestReadOnlyArrayOutputBuffers(t *testing.T) {
	r, cleanup, e := ArrayStrings([]string{"", "你好🙂", "USB Link"}).native()
	if e != nil {
		t.Fatal(e)
	}
	defer cleanup()
	v := Value{raw: r}
	for i := 0; i < 32; i++ {
		runtime.GC()
		got, e := v.Strings(3)
		if e != nil || len(got) != 3 || got[0] != "" || got[1] != "你好🙂" || got[2] != "USB Link" {
			t.Fatalf("BSTR array: %v %v", got, e)
		}
		items, e := v.Values(3)
		if e != nil {
			t.Fatal(e)
		}
		for j := range items {
			s, e := items[j].String()
			items[j].Clear()
			if e != nil || s != got[j] {
				t.Fatalf("element %d: %q %v", j, s, e)
			}
		}
	}
}
