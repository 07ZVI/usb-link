//go:build windows && amd64

package netconfig

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var icmpDLL = windows.NewLazySystemDLL("iphlpapi.dll")
var icmpCreate = icmpDLL.NewProc("IcmpCreateFile")
var icmpClose = icmpDLL.NewProc("IcmpCloseHandle")
var icmpEcho = icmpDLL.NewProc("IcmpSendEcho2Ex")

// ProbeWindowsICMPNative uses the real Windows stack, not synthesized bridge
// replies. Synchronous calls retain both buffers until completion; no APC,
// abandoned goroutine or cancellable native operation can outlive them.
func ProbeWindowsICMPNative(ctx context.Context, source, destination string, logger *log.Logger) error {
	return nativeStep(logger, "os_icmp", func() error {
		s, d, err := icmpPair(source, destination)
		if err != nil || ctx == nil {
			return errors.New("USB_ICMP_SCOPE_INVALID")
		}
		for _, p := range []*windows.LazyProc{icmpCreate, icmpClose, icmpEcho} {
			if err := p.Find(); err != nil {
				return errors.New("USB_ICMP_API_UNAVAILABLE")
			}
		}
		h, _, err := icmpCreate.Call()
		if h == 0 || h == ^uintptr(0) {
			return fmt.Errorf("USB_ICMP_OPEN_FAILED: %w", err)
		}
		defer icmpClose.Call(h)
		var failures []error
		for i := 0; i < 5; i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			timeout := time.Second
			if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
				timeout = time.Until(deadline)
			}
			if timeout < time.Millisecond {
				return context.DeadlineExceeded
			}
			var nonce [32]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return errors.New("USB_ICMP_NONCE_UNAVAILABLE")
			}
			// Enough for either reply header, 32 payload bytes, ICMP error and
			// IO_STATUS_BLOCK. No received pointer is trusted or dereferenced.
			var response [256]byte
			base := uintptr(unsafe.Pointer(&response[0]))
			count, _, err := icmpEcho.Call(h, 0, 0, 0, uintptr(s), uintptr(d), uintptr(unsafe.Pointer(&nonce[0])), uintptr(len(nonce)), 0, base, uintptr(len(response)), uintptr(timeout.Milliseconds()))
			runtime.KeepAlive(nonce)
			runtime.KeepAlive(response)
			if count != 1 {
				failures = append(failures, fmt.Errorf("USB_ICMP_REQUEST_FAILED: %w", err))
				continue
			}
			rtt, err := checkICMPEchoReply(response[:], nonce[:], base, d)
			if err != nil {
				failures = append(failures, err)
			} else if logger != nil {
				logger.Printf("WINDOWS_OS_ICMP_NATIVE sample=%d success=true rtt_ms=%d", i+1, rtt)
			}
		}
		return errors.Join(failures...)
	})
}
