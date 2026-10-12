//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"runtime"
	"unsafe"
)

type nativeRegistrationStore struct{ key registry.Key }

func (s nativeRegistrationStore) Read(name string) (registrationValue, error) {
	n, kind, e := s.key.GetValue(name, nil)
	if e == registry.ErrNotExist {
		return registrationValue{}, nil
	}
	if e != nil && e != registry.ErrShortBuffer {
		return registrationValue{}, e
	}
	if n < 0 || n > 65536 {
		return registrationValue{}, fmt.Errorf("INSTALL_REGISTRATION_VALUE_TOO_LARGE")
	}
	data := make([]byte, n)
	size, actual, e := s.key.GetValue(name, data)
	if e != nil || size != n || actual != kind {
		return registrationValue{}, fmt.Errorf("INSTALL_REGISTRATION_VALUE_CHANGED: %s: %v", name, e)
	}
	return registrationValue{true, kind, data}, nil
}
func (s nativeRegistrationStore) Write(name string, v registrationValue) error {
	var data uintptr
	if len(v.Data) > 0 {
		data = uintptr(unsafe.Pointer(&v.Data[0]))
	}
	code, _, _ := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegSetValueExW").Call(uintptr(s.key), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 0, uintptr(v.Kind), data, uintptr(len(v.Data)))
	runtime.KeepAlive(v.Data)
	if code != 0 {
		return windows.Errno(code)
	}
	return nil
}
func (s nativeRegistrationStore) Remove(name string) error {
	e := s.key.DeleteValue(name)
	if e == registry.ErrNotExist {
		return nil
	}
	return e
}
func (s nativeRegistrationStore) Sync() error {
	code, _, _ := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegFlushKey").Call(uintptr(s.key))
	if code != 0 {
		return windows.Errno(code)
	}
	return nil
}
