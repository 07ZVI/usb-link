//go:build windows && amd64

package ipadncm

import (
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"io"
	"strings"
	"syscall"
	"unsafe"
)

const photoPolicyRegistryPath = `SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`

var photoPolicyAdvapi = windows.NewLazySystemDLL("advapi32.dll")
var photoPolicyKTM = windows.NewLazySystemDLL("KtmW32.dll")

func photoPolicyReadValue(k registry.Key, name string) (photoPolicyValue, error) {
	buf := make([]byte, 4096)
	n, typ, e := k.GetValue(name, buf)
	if e == registry.ErrNotExist {
		return photoPolicyValue{}, nil
	}
	if e != nil || n > len(buf) {
		return photoPolicyValue{}, errors.New("PHOTO_POLICY_VALUE_UNREADABLE")
	}
	return photoPolicyValue{true, typ, buf[:n]}, nil
}
func photoPolicyReadKeys(root, list registry.Key) (photoPolicyRegistry, error) {
	s := photoPolicyRegistry{Entries: map[string]photoPolicyValue{}}
	var e error
	if root != 0 {
		if s.Deny, e = photoPolicyReadValue(root, "DenyInstanceIDs"); e != nil {
			return s, e
		}
		if s.Retroactive, e = photoPolicyReadValue(root, "DenyInstanceIDsRetroactive"); e != nil {
			return s, e
		}
	}
	if list == 0 {
		return s, nil
	}
	info, e := list.Stat()
	if e != nil || info.ValueCount > 64 || info.MaxValueNameLen > 64 || info.SubKeyCount != 0 {
		return s, errors.New("PHOTO_POLICY_LIST_UNSUPPORTED")
	}
	names, e := list.ReadValueNames(65)
	if e != nil && e != io.EOF {
		return s, e
	}
	if len(names) > 64 {
		return s, errors.New("PHOTO_POLICY_LIST_LIMIT")
	}
	for _, name := range names {
		v, e := photoPolicyReadValue(list, name)
		if e != nil {
			return s, e
		}
		if !v.Present {
			return s, errors.New("PHOTO_POLICY_REGISTRY_CHANGED")
		}
		s.Entries[strings.ToLower(name)] = v
	}
	return s, nil
}
func (b *photoPolicyNativeStore) readRegistry() (photoPolicyRegistry, error) {
	root, e := registry.OpenKey(registry.LOCAL_MACHINE, photoPolicyRegistryPath, registry.READ|registry.WOW64_64KEY)
	if e == registry.ErrNotExist {
		return photoPolicyRegistry{Entries: map[string]photoPolicyValue{}}, nil
	}
	if e != nil {
		return photoPolicyRegistry{}, photoWindowsFailure("PHOTO_POLICY_READ_FAILED", e)
	}
	defer root.Close()
	list, e := registry.OpenKey(registry.LOCAL_MACHINE, photoPolicyRegistryPath+`\DenyInstanceIDs`, registry.READ|registry.WOW64_64KEY)
	if e != nil && e != registry.ErrNotExist {
		return photoPolicyRegistry{}, photoWindowsFailure("PHOTO_POLICY_READ_FAILED", e)
	}
	if list != 0 {
		defer list.Close()
	}
	return photoPolicyReadKeys(root, list)
}
func photoPolicyTransactedKey(tx windows.Handle, path string) (registry.Key, error) {
	var key registry.Key
	var disposition uint32
	r, _, _ := photoPolicyAdvapi.NewProc("RegCreateKeyTransactedW").Call(uintptr(registry.LOCAL_MACHINE), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(path))), 0, 0, 0, uintptr(registry.READ|registry.WRITE|registry.WOW64_64KEY), 0, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&disposition)), uintptr(tx), 0)
	if r != 0 {
		return 0, photoWindowsFailure("PHOTO_POLICY_TRANSACTION_KEY_FAILED", syscall.Errno(r))
	}
	return key, nil
}
func photoPolicyWriteRaw(k registry.Key, name string, v photoPolicyValue) error {
	if !v.valid() {
		return errors.New("PHOTO_POLICY_VALUE_INVALID")
	}
	if !v.Present {
		e := k.DeleteValue(name)
		if e == registry.ErrNotExist {
			return nil
		}
		return e
	}
	var data uintptr
	if len(v.Data) > 0 {
		data = uintptr(unsafe.Pointer(&v.Data[0]))
	}
	r, _, _ := photoPolicyAdvapi.NewProc("RegSetValueExW").Call(uintptr(k), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 0, uintptr(v.Type), data, uintptr(len(v.Data)))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}
func (b *photoPolicyNativeStore) change(expected photoPolicyRegistry, changes []photoPolicyChange) error {
	// Transactions fail on concurrent non-transactional changes to these keys;
	// there is no check-then-overwrite fallback when KTM is unavailable.
	h, _, e := photoPolicyKTM.NewProc("CreateTransaction").Call(0, 0, 0, 0, 0, 2000, 0)
	if h == 0 || h == ^uintptr(0) {
		return photoWindowsFailure("PHOTO_POLICY_TRANSACTION_UNAVAILABLE", e)
	}
	tx := windows.Handle(h)
	defer windows.CloseHandle(tx)
	defer photoPolicyKTM.NewProc("RollbackTransaction").Call(h)
	root, e := photoPolicyTransactedKey(tx, photoPolicyRegistryPath)
	if e != nil {
		return e
	}
	defer root.Close()
	list, e := photoPolicyTransactedKey(tx, photoPolicyRegistryPath+`\DenyInstanceIDs`)
	if e != nil {
		return e
	}
	defer list.Close()
	current, e := photoPolicyReadKeys(root, list)
	if e != nil {
		return e
	}
	if !current.same(expected) {
		return errors.New("PHOTO_POLICY_REGISTRY_CHANGED")
	}
	for _, c := range changes {
		key, name := root, ""
		switch c.Name {
		case "deny":
			name = "DenyInstanceIDs"
		case "retroactive":
			name = "DenyInstanceIDsRetroactive"
		default:
			if !strings.HasPrefix(c.Name, "entry:") {
				return errors.New("PHOTO_POLICY_CHANGE_INVALID")
			}
			key = list
			name = strings.TrimPrefix(c.Name, "entry:")
			if len(name) < 1 || len(name) > 16 || strings.Trim(name, "0123456789") != "" {
				return errors.New("PHOTO_POLICY_CHANGE_INVALID")
			}
		}
		if e = photoPolicyWriteRaw(key, name, c.Value); e != nil {
			return photoWindowsFailure("PHOTO_POLICY_WRITE_FAILED", e)
		}
		read, e := photoPolicyReadValue(key, name)
		if e != nil || !read.same(c.Value) {
			return errors.New("PHOTO_POLICY_TRANSACTION_READBACK_FAILED")
		}
	}
	ok, _, e := photoPolicyKTM.NewProc("CommitTransaction").Call(h)
	if ok == 0 {
		return photoWindowsFailure("PHOTO_POLICY_TRANSACTION_CONFLICT", e)
	}
	return nil
}
