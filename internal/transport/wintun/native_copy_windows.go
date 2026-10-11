//go:build windows && amd64

package wintun

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"time"
	"unsafe"
)

// nativePointer represents a Wintun-owned, non-Go allocation. It must never be
// used for Go heap addresses, arithmetic or after the native packet is released.
//
//go:noescape
func nativePointer(address uintptr) unsafe.Pointer

func nativePacket(address uintptr, length int) []byte {
	if address == 0 || length < 1 || length > 65535 {
		panic("invalid native packet view")
	}
	return unsafe.Slice((*byte)(nativePointer(address)), length)
}

// VerifyNativeCopy checks the pointer ABI and Go/native copying in memory owned
// by this function, before any live adapter uses the fast copy path. RtlMoveMemory
// is retained solely as an independent native-copy oracle and local benchmark.
func VerifyNativeCopy() (nativeNS, goNS int64, err error) {
	if err = moveMemory.Find(); err != nil {
		return 0, 0, err
	}
	address, err := windows.VirtualAlloc(0, 65536, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return 0, 0, err
	}
	defer windows.VirtualFree(address, 0, windows.MEM_RELEASE)
	if uintptr(nativePointer(address)) != address {
		return 0, 0, fmt.Errorf("native pointer ABI mismatch")
	}
	for _, size := range []int{20, 1500, 65535} {
		input := make([]byte, size)
		for i := range input {
			input[i] = byte(i % 251)
		}
		target := nativePacket(address+1, size)
		copy(target, input)
		output := make([]byte, size)
		moveMemory.Call(uintptr(unsafe.Pointer(&output[0])), address+1, uintptr(size))
		runtime.KeepAlive(output)
		if !bytes.Equal(input, output) {
			return 0, 0, fmt.Errorf("native copy verification failed")
		}
		clear(target)
		moveMemory.Call(address+1, uintptr(unsafe.Pointer(&input[0])), uintptr(size))
		runtime.KeepAlive(input)
		output = append(output[:0], target...)
		if !bytes.Equal(input, output) {
			return 0, 0, fmt.Errorf("native read verification failed")
		}
	}
	const rounds = 4096
	input := make([]byte, 1500)
	target := nativePacket(address, 1500)
	start := time.Now()
	for i := 0; i < rounds; i++ {
		moveMemory.Call(address, uintptr(unsafe.Pointer(&input[0])), 1500)
	}
	nativeNS = time.Since(start).Nanoseconds() / rounds
	start = time.Now()
	for i := 0; i < rounds; i++ {
		copy(target, input)
	}
	goNS = time.Since(start).Nanoseconds() / rounds
	runtime.KeepAlive(input)
	return nativeNS, goNS, nil
}
