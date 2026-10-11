//go:build windows && amd64

package wintun

import (
	"errors"
	"golang.org/x/sys/windows"
	"path/filepath"
	"strings"
	"unsafe"
)

var moduleKernel = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleExW")

func holdWintunModule(d *windows.DLL, path string, proc *windows.Proc) error {
	if d == nil || d.Handle == 0 || proc == nil {
		return errors.New("WINTUN_MODULE_PIN_SOURCE_REQUIRED")
	}
	var actual [32768]uint16
	n, err := windows.GetModuleFileName(d.Handle, &actual[0], uint32(len(actual)))
	if err != nil || n == 0 || n >= uint32(len(actual)) || !strings.EqualFold(filepath.Clean(path), filepath.Clean(windows.UTF16ToString(actual[:n]))) {
		return errors.New("WINTUN_MODULE_PIN_SOURCE_CHANGED")
	}
	// A native function address identifies the loaded module, avoiding DLL-name
	// ambiguity. First read with unchanged refcount, then pin exactly this module.
	from := proc.Addr()
	lookup := func(flags uint32) error {
		var got windows.Handle
		r, _, e := moduleKernel.Call(uintptr(flags), from, uintptr(unsafe.Pointer(&got)))
		if r == 0 {
			return e
		}
		if got != d.Handle {
			return errors.New("WINTUN_MODULE_PIN_HANDLE_CHANGED")
		}
		return nil
	}
	if err = lookup(windows.GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT); err != nil {
		return err
	}
	return lifetimeModules.hold(uintptr(d.Handle), strings.ToLower(filepath.Clean(path)), func() error {
		return lookup(windows.GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | windows.GET_MODULE_HANDLE_EX_FLAG_PIN)
	})
}

// This is a fixed no-network diagnostic fixture, not an arbitrary adapter API.
type lifecycleProbeRequest struct{ hold bool }

// CreateLifecycleProbe never probes/adopts an existing device. The caller must
// own the dedicated probe lease, verified DLL and complete native absence.
// The synchronous official Create cannot be abandoned on context cancellation.
func CreateLifecycleProbe(path string, hold bool, beforeCreate func() error, observation *OwnedCreateObservation) (*Device, error) {
	if beforeCreate == nil || observation == nil {
		return nil, errors.New("WINTUN_PROBE_PRECHECK_REQUIRED")
	}
	return openNamedWithProbe(path, LifecycleProbeName, LifecycleProbeGUID, false, beforeCreate, observation, nil, &lifecycleProbeRequest{hold})
}
