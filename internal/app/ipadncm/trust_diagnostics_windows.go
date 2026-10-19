//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/buildinfo"
	"suhang/usbnet/internal/diagnostics/grouptrial"
	"suhang/usbnet/internal/security/deviceguard"
)

// Diagnostic observation is independent of connection success and uses no USB
// control transfer, Apple session, pairing file, driver or service mutation.
func StartTrustDiagnostics(ctx context.Context) {
	if buildinfo.LocalDiagnostics != "true" || ctx == nil || ctx.Err() != nil {
		return
	}
	started := time.Now()
	var nonce [12]byte
	runID := "utc-" + fmt.Sprint(started.UnixNano())
	if _, err := rand.Read(nonce[:]); err == nil {
		runID = hex.EncodeToString(nonce[:])
	}
	if !trustDiagnostics.start(started, runID) {
		return
	}
	go func() {
		defer func() { trustDiagnostics.stop(time.Now(), currentSoftwareAttempt()) }()
		notices, unsubscribe, err := deviceguard.SubscribeFilteredChanges(func(id string) bool { return strings.HasPrefix(strings.ToUpper(id), `USB\VID_05AC&PID_12`) })
		if err != nil {
			trustDiagnostics.subscription(time.Now(), currentSoftwareAttempt(), "unavailable")
		} else {
			defer unsubscribe()
			trustDiagnostics.subscription(time.Now(), currentSoftwareAttempt(), "subscribed")
		}
		sample := func() {
			if !connectionTimingMasterEnabled() {
				return
			}
			service := queryTrustAMDS()
			trustDiagnostics.amds(time.Now(), currentSoftwareAttempt(), service)
			readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			pnp := queryTrustPNP(readCtx)
			cancel()
			trustDiagnostics.pnp(time.Now(), currentSoftwareAttempt(), pnp)
		}
		// Subscribe before the independent baseline. Neither a failed connection
		// attempt nor absent device disables subsequent one-second observations.
		sample()
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		var noticeAt time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				sample()
			case <-notices:
				// The CM subscription already coalesces callbacks. At most one
				// delivered hint per interval is retained; the next tick samples.
				now := time.Now()
				if noticeAt.IsZero() || now.Sub(noticeAt) >= time.Second {
					trustDiagnostics.event(now, currentSoftwareAttempt(), "pnp_notice", "coalesced_delivery_hint", "")
					noticeAt = now
				} else {
					trustDiagnostics.suppressNoticeHint()
				}
			}
		}
	}()
}

func trustWindowsReadCode(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return "access_denied"
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		return "not_installed"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "query_failed"
	}
}

func queryTrustAMDS() (r trustServiceState) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		r.Read = trustWindowsReadCode(err)
		return
	}
	defer windows.CloseServiceHandle(scm)
	h, err := windows.OpenService(scm, windows.StringToUTF16Ptr("Apple Mobile Device Service"), windows.SERVICE_QUERY_STATUS)
	if err != nil {
		r.Read = trustWindowsReadCode(err)
		return
	}
	defer windows.CloseServiceHandle(h)
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	err = windows.QueryServiceStatusEx(h, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed)
	r.Read = trustWindowsReadCode(err)
	if err != nil {
		return
	}
	if status.CurrentState < 1 || status.CurrentState > 7 {
		r.Read = "invalid_state"
		return
	}
	r.State, r.PID = status.CurrentState, status.ProcessId
	return
}

func queryTrustPNP(ctx context.Context) (r trustPNPState) {
	s := inventoryPnP(ctx)
	RecordConnectionEnvironmentPNP(s)
	r.Read = "ok"
	if s.Error != "" {
		switch s.Error {
		case "WIN32_5":
			r.Read = "access_denied"
		case "TIME_LIMIT":
			r.Read = "timeout"
		case "PNP_ENUM_LIMIT":
			r.Read = "enumeration_limit"
		default:
			r.Read = "query_failed"
		}
		if ctx.Err() != nil {
			r.Read = trustWindowsReadCode(ctx.Err())
		}
		return
	}
	for _, n := range s.Nodes {
		prefix := strings.ToUpper(n.IDPrefix)
		if prefix != `USB\VID_05AC&PID_12AB` && !strings.HasPrefix(prefix, `USB\VID_05AC&PID_12AB&`) {
			continue
		}
		role := "other"
		if prefix == `USB\VID_05AC&PID_12AB` {
			role = "R"
			r.Roots++
		} else {
			for _, mi := range []string{"00", "01", "02", "04", "03", "05"} {
				if strings.HasSuffix(prefix, "&MI_"+mi) {
					role = mi
					break
				}
			}
		}
		service := "U"
		switch strings.ToLower(n.Service) {
		case "usbccgp":
			service = "C"
		case "usbncm":
			service = "N"
			r.Controls++
		case "usbaapl", "usbaapl64":
			service = "A"
		case "winusb":
			service = "W"
		case "wudfwpdmtp":
			service = "P"
		case "wudfrd":
			service = "F"
		case "usbscan":
			service = "S"
		case "":
			service = "X"
		}
		r.Nodes = append(r.Nodes, trustNodeState{Role: role, Service: service, Problem: n.Problem, Readable: nodeCMReadable(n), Started: grouptrial.NativeStartObserved(n.Problem, n.StateError, n.DevNodeStatus), Restart: grouptrial.NeedsWindowsRestart(n.DevNodeStatus)})
	}
	return r
}
