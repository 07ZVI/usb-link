//go:build windows && amd64

package connectioninstall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"
)

type coreSelfSourcePin struct {
	path       string
	file       *os.File
	identity   windows.ByHandleFileInformation
	fileID     coreSelfFileID
	sha        string
	references int
}

// FileIdInfo preserves the full identifier on ReFS, where the legacy 64-bit
// FileIndex is explicitly not guaranteed unique. The comparison is from two
// live handles; a pathname or timestamp never supplies this identity.
type coreSelfFileID struct {
	Volume uint64
	ID     [16]byte
}

func readCoreSelfFileID(h windows.Handle) (v coreSelfFileID, e error) {
	e = windows.GetFileInformationByHandleEx(h, windows.FileIdInfo, (*byte)(unsafe.Pointer(&v)), uint32(unsafe.Sizeof(v)))
	if e != nil {
		return v, fmt.Errorf("CORE_SELF_PIN_FILE_ID_UNREADABLE")
	}
	return v, nil
}

var coreSelfPin struct {
	sync.Mutex
	value *coreSelfSourcePin
}

// PinCoreSelfSource pins only this process's already owned installed executable.
// Its immutable read handle denies write/delete sharing. Callers close their
// reference after UI/service workers are joined; target/upgrade files never use
// this optimization. Neither a timestamp nor a TTL substitutes for content proof.
func PinCoreSelfSource(exe string) (func() error, error) {
	self, e := os.Executable()
	if e != nil || !filepath.IsAbs(exe) || !strings.EqualFold(filepath.Clean(exe), filepath.Clean(self)) || VerifyCoreExecutable(exe) != nil {
		return nil, fmt.Errorf("CORE_SELF_PIN_SOURCE_UNPROVEN")
	}
	coreSelfPin.Lock()
	defer coreSelfPin.Unlock()
	if current := coreSelfPin.value; current != nil {
		if !strings.EqualFold(current.path, exe) || verifyCoreSelfPin(current) != nil {
			return nil, fmt.Errorf("CORE_SELF_PIN_CHANGED")
		}
		current.references++
		return coreSelfPinCloser(current), nil
	}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(exe), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(h), exe)
	if f == nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("CORE_SELF_PIN_HANDLE_INVALID")
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	v := &coreSelfSourcePin{path: exe, file: f, references: 1}
	if e = protectedCoreSelfIdentity(h, &v.identity); e != nil {
		return nil, e
	}
	if v.fileID, e = readCoreSelfFileID(h); e != nil {
		return nil, e
	}
	size := int64(uint64(v.identity.FileSizeHigh)<<32 | uint64(v.identity.FileSizeLow))
	if size < 1024 || size > 256*1024*1024 {
		return nil, fmt.Errorf("CORE_SELF_PIN_SIZE_INVALID")
	}
	hash := sha256.New()
	n, e := io.Copy(hash, io.LimitReader(f, 256*1024*1024+1))
	if e != nil || n != size {
		return nil, fmt.Errorf("CORE_SELF_PIN_HASH_FAILED")
	}
	v.sha = hex.EncodeToString(hash.Sum(nil))
	if e = verifyCoreSelfPin(v); e != nil {
		return nil, e
	}
	root, e := Root()
	if e != nil {
		return nil, e
	}
	bound, e := coreProtectedRead(filepath.Join(root, coreBindingFile), false, true)
	binding, decodeErr := parseCoreBinding(bound)
	if e != nil || decodeErr != nil || !strings.EqualFold(binding.Executable, exe) || binding.SHA256 != v.sha {
		return nil, fmt.Errorf("CORE_SELF_PIN_BINDING_UNPROVEN")
	}
	coreSelfPin.value = v
	ok = true
	return coreSelfPinCloser(v), nil
}

func coreSelfPinCloser(v *coreSelfSourcePin) func() error {
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			coreSelfPin.Lock()
			defer coreSelfPin.Unlock()
			if coreSelfPin.value != v || v.references <= 0 {
				result = fmt.Errorf("CORE_SELF_PIN_REFERENCE_CHANGED")
				return
			}
			v.references--
			if v.references == 0 {
				// Hash readers hold this same mutex until all fresh proofs complete.
				coreSelfPin.value = nil
				result = v.file.Close()
			}
		})
		return result
	}
}

func protectedCoreSelfIdentity(h windows.Handle, out *windows.ByHandleFileInformation) error {
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || !coreFileACLValid(sd) || windows.GetFileInformationByHandle(h, out) != nil || out.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || out.NumberOfLinks != 1 {
		return fmt.Errorf("CORE_SELF_PIN_FILE_PROTECTION_CHANGED")
	}
	return nil
}

func sameCoreSelfFile(a, b windows.ByHandleFileInformation) bool {
	return a.VolumeSerialNumber == b.VolumeSerialNumber && a.FileIndexHigh == b.FileIndexHigh && a.FileIndexLow == b.FileIndexLow && a.FileSizeHigh == b.FileSizeHigh && a.FileSizeLow == b.FileSizeLow && a.NumberOfLinks == 1 && b.NumberOfLinks == 1
}

// The tiny authorization documents are deliberately reread. A live immutable
// source never makes a changed receipt, ACL, path mapping or service trusted.
func verifyCoreSelfPin(v *coreSelfSourcePin) error {
	root, e := protectedRoot(false)
	if e != nil || filepath.Base(v.path) != BinaryName || !strings.EqualFold(filepath.Dir(filepath.Dir(v.path)), root) {
		return fmt.Errorf("CORE_SELF_PIN_ROOT_CHANGED")
	}
	for _, p := range []string{root, filepath.Join(root, "product-id.txt"), filepath.Dir(v.path), filepath.Join(filepath.Dir(v.path), "ownership.json")} {
		if _, e = coreProtectedRead(p, p == root || p == filepath.Dir(v.path), false); e != nil {
			return e
		}
	}
	marker, e := coreProtectedRead(filepath.Join(root, "product-id.txt"), false, true)
	if e != nil || string(marker) != ProductID {
		return fmt.Errorf("CORE_SELF_PIN_MARKER_CHANGED")
	}
	raw, e := coreProtectedRead(filepath.Join(filepath.Dir(v.path), "ownership.json"), false, true)
	var receipt Receipt
	if e != nil || len(raw) > 4096 || json.Unmarshal(raw, &receipt) != nil || receipt.Product != ProductID || !versionPattern.MatchString(receipt.Version) || filepath.Base(filepath.Dir(v.path)) != receipt.Version || receipt.SHA != v.sha {
		return fmt.Errorf("CORE_SELF_PIN_RECEIPT_CHANGED")
	}
	var held windows.ByHandleFileInformation
	if e = protectedCoreSelfIdentity(windows.Handle(v.file.Fd()), &held); e != nil || !sameCoreSelfFile(v.identity, held) {
		return fmt.Errorf("CORE_SELF_PIN_HANDLE_CHANGED")
	}
	heldID, e := readCoreSelfFileID(windows.Handle(v.file.Fd()))
	if e != nil || heldID != v.fileID {
		return fmt.Errorf("CORE_SELF_PIN_HANDLE_ID_CHANGED")
	}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(v.path), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	var current windows.ByHandleFileInformation
	if e = protectedCoreSelfIdentity(h, &current); e != nil || !sameCoreSelfFile(held, current) {
		return fmt.Errorf("CORE_SELF_PIN_PATH_CHANGED")
	}
	currentID, e := readCoreSelfFileID(h)
	if e != nil || currentID != heldID {
		return fmt.Errorf("CORE_SELF_PIN_PATH_ID_CHANGED")
	}
	return nil
}

func pinnedCoreSelfHash(path string) (string, bool, error) {
	coreSelfPin.Lock()
	defer coreSelfPin.Unlock()
	v := coreSelfPin.value
	if v == nil || !filepath.IsAbs(path) || !strings.EqualFold(filepath.Clean(path), filepath.Clean(v.path)) {
		return "", false, nil
	}
	if e := verifyCoreSelfPin(v); e != nil {
		return "", true, e
	}
	return v.sha, true, nil
}
