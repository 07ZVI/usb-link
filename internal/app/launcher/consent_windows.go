//go:build windows && amd64

package launcher

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"suhang/usbnet/internal/app/ipadncm"
	"sync/atomic"
	"unsafe"
)

func dialog(s string, f uintptr) uintptr {
	if coreProcessMode && f&0xf == 4 {
		yes, _ := ipadncm.NativePanel("USB Link", s, "同意並繼續", nil)
		if yes {
			return 6
		}
		return 7
	}
	if remoteInstallID != "" || coreProcessMode {
		fmt.Fprintln(os.Stderr, s)
		return 0
	}
	p, _ := windows.UTF16PtrFromString(s)
	t, _ := windows.UTF16PtrFromString("USB Link")
	v, _, _ := windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(t)), f)
	return v
}

type softwareConsentOwner struct{ ctx context.Context }

var softwareConsentContext atomic.Pointer[softwareConsentOwner]

func softwareReconnectConsentContext() context.Context {
	if owner := softwareConsentContext.Load(); owner != nil {
		return owner.ctx
	}
	return nil
}

func applicationConsent() bool {
	if authorization == nil {
		return false
	}
	allowed := authorization.Allow()
	ownerCtx := softwareReconnectConsentContext()
	if !allowed {
		// Canceling this attempt for an already admitted software action is not a
		// fresh refusal of that action. An explicit security failure still revokes it.
		if authorization.SecurityFailure() != "" || ownerCtx != nil && ownerCtx.Err() == nil {
			ipadncm.ClearIPadSoftwareReconnectScope()
		} else {
			ipadncm.ForgetIdleIPadSoftwareReconnectScope("USB consent/context no longer current")
		}
		return false
	}
	if s := ipadncm.IPadSoftwareReconnectSnapshot(); ownerCtx != nil && ownerCtx.Err() == nil && s.Available && !s.Busy {
		if err := ipadncm.CaptureIPadSoftwareReconnectScope(ownerCtx, authorization); err != nil {
			ipadncm.ForgetIdleIPadSoftwareReconnectScope(err.Error())
		}
	}
	return true
}

func ctxForInstall() context.Context {
	if owner := softwareConsentContext.Load(); owner != nil {
		return owner.ctx
	}
	return context.Background()
}
