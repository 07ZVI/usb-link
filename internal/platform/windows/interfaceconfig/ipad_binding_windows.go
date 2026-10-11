//go:build windows && amd64

package interfaceconfig

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"unsafe"
)

const ipadBindingFile = "usb-ipad-persistent-binding.json"

func readIPadBinding(dir string) (IPadPersistentBinding, bool, error) {
	var zero IPadPersistentBinding
	if !configDirectoryProtected(dir) {
		return zero, false, errors.New("USB_SECONDARY_BINDING_STORE_UNPROVEN")
	}
	p, _ := windows.UTF16PtrFromString(filepath.Join(dir, ipadBindingFile))
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return zero, false, nil
	}
	if e != nil {
		return zero, false, errors.New("USB_SECONDARY_BINDING_UNREADABLE")
	}
	f := os.NewFile(uintptr(h), ipadBindingFile)
	if f == nil {
		windows.CloseHandle(h)
		return zero, false, errors.New("USB_SECONDARY_BINDING_UNREADABLE")
	}
	defer f.Close()
	if !secondaryHandleProtected(h) {
		return zero, false, errors.New("USB_SECONDARY_BINDING_PROTECTION_UNPROVEN")
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil {
		return zero, false, errors.New("USB_SECONDARY_BINDING_UNREADABLE")
	}
	v, e := decodeIPadBinding(b)
	return v, true, e
}
func writeIPadBinding(dir string, next IPadPersistentBinding, old *IPadPersistentBinding) error {
	if !configDirectoryProtected(dir) {
		return errors.New("USB_SECONDARY_BINDING_STORE_UNPROVEN")
	}
	b, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if _, e = decodeIPadBinding(b); e != nil {
		return e
	}
	current, found, e := readIPadBinding(dir)
	if e != nil {
		return e
	}
	if old == nil {
		if found || next.State != "pending" {
			return errors.New("USB_SECONDARY_BINDING_ALREADY_EXISTS")
		}
	} else if !found || !sameIPadBinding(current, *old) || !ipadBindingTransition(current, next) {
		return errors.New("USB_SECONDARY_BINDING_CHANGED")
	}
	sd, e := windows.SecurityDescriptorFromString(configFileSDDL)
	if e != nil {
		return errors.New("USB_SECONDARY_BINDING_ACL_UNPROVEN")
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	temp := filepath.Join(dir, "usb-ipad-binding-"+hex.EncodeToString(nonce[:])+".tmp")
	defer os.Remove(temp)
	tp, _ := windows.UTF16PtrFromString(temp)
	h, e := windows.CreateFile(tp, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return errors.New("USB_SECONDARY_BINDING_CREATE_FAILED")
	}
	f := os.NewFile(uintptr(h), temp)
	if f == nil {
		windows.CloseHandle(h)
		return errors.New("USB_SECONDARY_BINDING_WRITE_FAILED")
	}
	if !secondaryHandleProtected(h) {
		f.Close()
		return errors.New("USB_SECONDARY_BINDING_PROTECTION_UNPROVEN")
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return errors.New("USB_SECONDARY_BINDING_WRITE_FAILED")
	}
	check, present, e := readIPadBinding(dir)
	if e != nil || (old == nil && present) || (old != nil && (!present || !sameIPadBinding(check, *old))) {
		return errors.New("USB_SECONDARY_BINDING_CHANGED")
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if old != nil {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	dst, _ := windows.UTF16PtrFromString(filepath.Join(dir, ipadBindingFile))
	if windows.MoveFileEx(tp, dst, flags) != nil {
		return errors.New("USB_SECONDARY_BINDING_COMMIT_FAILED")
	}
	got, present, e := readIPadBinding(dir)
	x, _ := json.Marshal(got)
	if e != nil || !present || !bytes.Equal(x, b) {
		return errors.New("USB_SECONDARY_BINDING_READBACK_FAILED")
	}
	return nil
}

func ReadIPadPersistentBinding(dir string) (IPadPersistentBinding, bool, error) {
	done, e := lockConfig()
	if e != nil {
		return IPadPersistentBinding{}, false, e
	}
	defer done()
	return readIPadBinding(dir)
}

// Capture happens before HostFlags, DAD or native IP mutation.
func CaptureIPadPersistentIntent(ctx context.Context, dir string, v IPadPersistentBinding, owner func() error) error {
	done, e := lockConfig()
	if e != nil {
		return e
	}
	defer done()
	if e = fresh(ctx, v.Scope, owner); e != nil {
		return e
	}
	r, found, e := readConfigReceiptFile(dir)
	if e != nil {
		return e
	}
	if found && (r.RestoreRequested || ipadOriginalsPending(r)) {
		return errors.New("USB_IPAD_EXISTING_ORIGINALS_UNBOUND")
	}
	return writeIPadBinding(dir, v, nil)
}
func CheckpointIPadPersistentAddress(ctx context.Context, dir string, old, next IPadPersistentBinding, owner func() error) error {
	done, e := lockConfig()
	if e != nil {
		return e
	}
	defer done()
	if (next.State != "address" && next.State != "ephemeral") || !ipadBindingTransition(old, next) {
		return errors.New("USB_IPAD_ADDRESS_CHECKPOINT_INVALID")
	}
	if e = fresh(ctx, next.Scope, owner); e != nil {
		return e
	}
	return writeIPadBinding(dir, next, &old)
}

// Ready publication and original/Store/Active proof share the config mutex.
func CheckpointIPadPersistentReady(ctx context.Context, dir string, old, next IPadPersistentBinding, owner func() error, profile ProfileOps) error {
	done, e := lockConfig()
	if e != nil {
		return e
	}
	defer done()
	if next.State != "ready" || !ipadBindingTransition(old, next) {
		return errors.New("USB_IPAD_READY_CHECKPOINT_INVALID")
	}
	r, found, e := readConfigReceiptFile(dir)
	if e != nil || !found || r.RestoreRequested {
		return errors.New("USB_IPAD_ORIGINAL_UNPROVEN")
	}
	a, e := verifyPersistentModeUnlocked(ctx, dir, next.Scope, owner, profile, next.Plan.AddressMode, next.Plan.CreatedAt)
	if e != nil {
		return e
	}
	b, e := verifyPersistentModeUnlocked(ctx, dir, next.Scope, owner, profile, next.Plan.AddressMode, next.Plan.CreatedAt)
	if e != nil {
		return e
	}
	if a != b || a.ReceiptSHA256 != next.Plan.PersistentSHA256 || a.Created != next.Plan.CreatedAt {
		return errors.New("USB_IPAD_READY_PROOF_CHANGED")
	}
	return writeIPadBinding(dir, next, &old)
}
func BeginIPadPersistentRestore(ctx context.Context, dir string, v IPadPersistentBinding, owner func() error) error {
	done, e := lockConfig()
	if e != nil {
		return e
	}
	defer done()
	r, found, e := readConfigReceiptFile(dir)
	if e != nil || !found || !r.RestoreRequested {
		return errors.New("USB_IPAD_RESTORE_NOT_REQUESTED")
	}
	if v.State == "ready" {
		original := false
		for _, o := range r.Persistent {
			if o.Scope == v.Scope && o.Profile != nil && o.AppliedAddress != nil && persistentDigest(o) == v.Plan.PersistentSHA256 {
				original = true
			}
		}
		if !original {
			return errors.New("USB_IPAD_READY_ORIGINAL_MISSING_OR_CHANGED")
		}
	}
	if e = fresh(ctx, v.Scope, owner); e != nil {
		return e
	}
	if v.State == "restoring" {
		got, f, e := readIPadBinding(dir)
		if e != nil || !f || !sameIPadBinding(got, v) {
			return errors.New("USB_IPAD_BINDING_CHANGED")
		}
		return nil
	}
	next := v
	next.State = "restoring"
	return writeIPadBinding(dir, next, &v)
}
func FinishIPadPersistentBinding(ctx context.Context, dir string, v IPadPersistentBinding, owner func() error) error {
	done, e := lockConfig()
	if e != nil {
		return e
	}
	defer done()
	if e = fresh(ctx, v.Scope, owner); e != nil {
		return e
	}
	r, found, e := readConfigReceiptFile(dir)
	if e != nil {
		return e
	}
	if !found || !r.RestoreRequested || ipadOriginalsPending(r) {
		return errors.New("USB_IPAD_ORIGINALS_REMAIN")
	}
	got, f, e := readIPadBinding(dir)
	if e != nil || !f || !sameIPadBinding(got, v) {
		return errors.New("USB_IPAD_BINDING_CHANGED")
	}
	if os.Remove(filepath.Join(dir, ipadBindingFile)) != nil {
		return errors.New("USB_IPAD_BINDING_DELETE_FAILED")
	}
	_, f, e = readIPadBinding(dir)
	if e != nil || f {
		return errors.New("USB_IPAD_BINDING_ABSENCE_UNPROVEN")
	}
	return nil
}

// An unsuccessful capture may retire only after exact native cleanup and every
// recorded original has been independently restored. Ready is never abandoned.
func FinishIPadFailedIntent(ctx context.Context, dir string, v IPadPersistentBinding, owner func() error) error {
	done, e := lockConfig()
	if e != nil {
		return e
	}
	defer done()
	if v.State == "ready" || v.State == "restoring" {
		return errors.New("USB_IPAD_READY_CANNOT_BE_ABANDONED")
	}
	if e = fresh(ctx, v.Scope, owner); e != nil {
		return e
	}
	r, f, e := readConfigReceiptFile(dir)
	if e != nil {
		return e
	}
	if f && (ipadOriginalsPending(r)) {
		return errors.New("USB_IPAD_ORIGINALS_REMAIN")
	}
	got, f, e := readIPadBinding(dir)
	if e != nil || !f || !sameIPadBinding(got, v) {
		return errors.New("USB_IPAD_BINDING_CHANGED")
	}
	if os.Remove(filepath.Join(dir, ipadBindingFile)) != nil {
		return errors.New("USB_IPAD_BINDING_DELETE_FAILED")
	}
	_, f, e = readIPadBinding(dir)
	if e != nil || f {
		return errors.New("USB_IPAD_BINDING_ABSENCE_UNPROVEN")
	}
	return nil
}

// Fixed-role observation, never a native authorization or readiness proof.
func ReadIPadOriginalsState(dir string) (exists, pending, restore bool, e error) {
	done, e := lockConfig()
	if e != nil {
		return false, false, false, e
	}
	defer done()
	r, f, e := readConfigReceiptFile(dir)
	if e != nil || !f {
		return f, false, false, e
	}
	return true, ipadOriginalsPending(r), r.RestoreRequested, nil
}

// Called only by the local confirmed-uninstall coordinator. This records
// intent even when a crash preceded the first original-value write.
func RequestIPadPersistentRestore(dir string) error {
	done, e := lockConfig()
	if e != nil {
		return e
	}
	defer done()
	_, binding, e := readIPadBinding(dir)
	if e != nil || !binding {
		return e
	}
	r, f, e := readConfigReceiptFile(dir)
	if e != nil {
		return e
	}
	if !f {
		r = configReceipt{Version: 1}
	}
	r.RestoreRequested = true
	return writeConfigReceiptFile(dir, r, f)
}

// Cleanup may verify a completed owned row with the feature OFF, but cannot
// produce ordinary network/firewall proof or mutate/re-capture any original.
func VerifyIPadPersistentCleanup(ctx context.Context, dir string, v IPadPersistentBinding, owner func() error, profile ProfileOps) error {
	done, e := lockConfig()
	if e != nil {
		return e
	}
	defer done()
	got, f, e := readIPadBinding(dir)
	if e != nil || !f || !sameIPadBinding(got, v) || v.State != "ready" {
		return errors.New("USB_IPAD_CLEANUP_BINDING_UNPROVEN")
	}
	r, f, e := readConfigReceiptFile(dir)
	if e != nil || !f || r.RestoreRequested {
		return errors.New("USB_IPAD_CLEANUP_UNINSTALL_PENDING")
	}
	mode := "retained_runtime"
	if v.Plan.AddressMode == "legacy" {
		mode = "retained_legacy"
	}
	observe := func() (ActiveOwnership, error) {
		a, e := verifyPersistentModeUnlocked(ctx, dir, v.Scope, owner, profile, mode, v.Plan.CreatedAt)
		if e == nil {
			return a, nil
		}
		// A completed binding plus immutable original and identical volatile map
		// may observe the reboot-created infinite row. No new target is adopted.
		return verifyPersistentModeUnlocked(ctx, dir, v.Scope, owner, profile, "persistent", 0)
	}
	a, e := observe()
	if e != nil {
		return e
	}
	b, e := observe()
	if e != nil {
		return e
	}
	if a != b || a.ReceiptSHA256 != v.Plan.PersistentSHA256 {
		return errors.New("USB_IPAD_CLEANUP_PROOF_CHANGED")
	}
	if b.Created != v.Plan.CreatedAt {
		if b.AddressMode != "persistent" {
			return errors.New("USB_IPAD_CLEANUP_CREATED_CHANGED")
		}
		next := v
		next.Plan.CreatedAt = b.Created
		next.Plan.AddressMode = "persistent"
		return writeIPadBinding(dir, next, &v)
	}
	return nil
}
