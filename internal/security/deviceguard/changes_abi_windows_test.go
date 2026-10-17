//go:build windows && amd64 && usblink_local_remote

package deviceguard

import (
	"encoding/binary"
	"runtime"
	"syscall"
	"testing"
	"unicode/utf16"
	"unsafe"
)

// Invoke only our callback with synthetic memory, never a device or a native
// registration. The fifth x64 stack slot deliberately has dirty upper bits.
func TestChangeCallbackHonorsNativeDWORDArguments(t *testing.T) {
	const instance = `USB\VID_05AC&PID_12AB\SYNTHETIC_CALLBACK`
	units := append(utf16.Encode([]rune(instance)), 0)
	data := make([]byte, 8+len(units)*2)
	binary.LittleEndian.PutUint32(data, 2)
	for i, value := range units {
		binary.LittleEndian.PutUint16(data[8+i*2:], value)
	}
	stream, err := newChangeMetadataStream()
	if err != nil {
		t.Fatal(err)
	}
	changes.Lock()
	changes.next++
	id := changes.next
	changes.filters[id] = func(value string) bool { return value == instance }
	changes.kinds[id], changes.metadata[id] = 2, stream
	changes.Unlock()
	t.Cleanup(func() {
		changes.Lock()
		delete(changes.filters, id)
		delete(changes.kinds, id)
		delete(changes.metadata, id)
		changes.Unlock()
		stream.StopAdmission()
	})
	var pin runtime.Pinner
	pin.Pin(&data[0])
	defer pin.Unpin()
	call := func(size uintptr) {
		r, _, _ := syscall.SyscallN(changeCallback, 0, id, 0xdeadbeef00000007, uintptr(unsafe.Pointer(&data[0])), size)
		if r != 0 {
			t.Fatal(r)
		}
	}
	call(0xdeadbeef00000000 | uintptr(len(data)))
	select {
	case event := <-stream.Events():
		if event.Product != 0x12ab || event.Action != "instance_enumerated" {
			t.Fatal(event)
		}
	default:
		t.Fatal("DWORD stack padding caused a valid event to be discarded")
	}
	for _, size := range []uintptr{0, 9, 4097} {
		call(0xdeadbeef00000000 | size)
	}
	if r, _, _ := syscall.SyscallN(changeCallback, 0, id, 7, 0, uintptr(len(data))); r != 0 {
		t.Fatal(r)
	}
	runtime.KeepAlive(data)
	if stats := stream.Stats(); stats.Observed != 1 || stats.Rejected != 4 || stats.RejectedSize != 4 {
		t.Fatal(stats)
	}
}
