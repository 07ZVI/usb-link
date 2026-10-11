package netconfig

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net/netip"
	"sync/atomic"
	"time"
)

// SetNativeNetworkEnabled is an internal, process-local selection. The parent
// sets it only from its protected bounded settings; the verified bridge gets an
// explicit argument. No environment or user-writable file selects this path.
var nativeNetwork atomic.Bool

func SetNativeNetworkEnabled(enabled bool) { nativeNetwork.Store(enabled) }
func NativeNetworkEnabled() bool           { return nativeNetwork.Load() }

func nativeCategoryAllows(current, desired uint32, expected *uint32, allowAlreadyRestored bool) bool {
	if current > 1 || desired > 1 || (expected != nil && *expected > 1) {
		return false
	}
	return expected == nil || current == *expected || (allowAlreadyRestored && current == desired)
}

func nativeStep(logger *log.Logger, phase string, call func() error) error {
	start := time.Now()
	complete := beginNetworkTiming(phase)
	err := call()
	complete(err)
	if logger != nil {
		logger.Printf("USB_NATIVE_NETWORK_STEP phase=%s elapsed_ms=%d success=%t", phase, time.Since(start).Milliseconds(), err == nil)
	}
	if err != nil && NativeOperationValid(phase) {
		return &NativeStepFailure{Operation: phase, Cause: err}
	}
	return err
}

func icmpPair(source, destination string) (uint32, uint32, error) {
	// Fixed USB peers only; a diagnostic cannot become an arbitrary network probe.
	allowed := (source == "10.6.9.1" && (destination == "10.6.9.2" || destination == "10.6.9.3")) || (source == "10.77.0.2" && destination == "10.77.0.1")
	if !allowed {
		return 0, 0, errors.New("USB_ICMP_SCOPE_INVALID")
	}
	s, d := netip.MustParseAddr(source).As4(), netip.MustParseAddr(destination).As4()
	return binary.LittleEndian.Uint32(s[:]), binary.LittleEndian.Uint32(d[:]), nil
}

// The documented 64-bit ICMP_ECHO_REPLY32 carries a POINTER_32. Recover only
// an offset into this bounded response allocation, never dereference that API
// pointer. This also accepts the native-pointer representation of synchronous
// replies without allowing either representation to point outside our buffer.
func checkICMPEchoReply(reply, nonce []byte, base uintptr, destination uint32) (uint32, error) {
	if len(reply) < 28 || len(nonce) != 32 || binary.LittleEndian.Uint32(reply[:4]) != destination || binary.LittleEndian.Uint32(reply[4:8]) != 0 || int(binary.LittleEndian.Uint16(reply[12:14])) != len(nonce) {
		return 0, errors.New("USB_ICMP_REPLY_UNPROVEN")
	}
	offset := uint64(binary.LittleEndian.Uint32(reply[16:20]) - uint32(base))
	if offset < 28 || offset+uint64(len(nonce)) > uint64(len(reply)) || !bytes.Equal(reply[int(offset):int(offset)+len(nonce)], nonce) {
		return 0, errors.New("USB_ICMP_NONCE_UNPROVEN")
	}
	return binary.LittleEndian.Uint32(reply[8:12]), nil
}
