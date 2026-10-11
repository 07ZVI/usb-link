//go:build windows && amd64

package netconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"suhang/usbnet/internal/transport/wintun"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintunTrustDLL       = windows.NewLazySystemDLL("wintrust.dll")
	wintunProviderData   = wintunTrustDLL.NewProc("WTHelperProvDataFromStateData")
	wintunProviderSigner = wintunTrustDLL.NewProc("WTHelperGetProvSignerFromChain")
	wintunProviderCert   = wintunTrustDLL.NewProc("WTHelperGetProvCertFromChain")
	wintunCopyNative     = windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlMoveMemory")
)

type verifiedWintunLease struct {
	mu        sync.Mutex
	file      *os.File
	ancestors []windows.Handle
}

func (p *verifiedWintunLease) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var err error
	if p.file != nil {
		err = p.file.Close()
		p.file = nil
	}
	for i := len(p.ancestors) - 1; i >= 0; i-- {
		err = errors.Join(err, windows.CloseHandle(p.ancestors[i]))
	}
	p.ancestors = nil
	return err
}

// VerifyWintunNative preserves Windows' default Authenticode trust policy and
// verifies the primary signer CN without spawning PowerShell. Callers loading
// the DLL should use PinVerifiedWintunNative and hold its lease across loading.
func VerifyWintunNative(path string, l *log.Logger) error {
	p, err := PinVerifiedWintunNative(path, l)
	if err != nil {
		return err
	}
	return p.Close()
}

// PinVerifiedWintunNative returns a lease preventing write, deletion, or ancestor
// rename while the verified DLL is loaded. The caller must close it after
// OpenNamed returns. WinVerifyTrust is synchronous: there is no fake timeout or
// early handle release, and OS trust-policy network activity can delay return.
func PinVerifiedWintunNative(path string, l *log.Logger) (io.Closer, error) {
	p, err := pinWintunFile(path)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = p.Close()
		}
	}()
	h := windows.Handle(p.file.Fd())
	before, err := wintunHandleInfo(h, false)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(p.file, 16*1024*1024+1))
	if err != nil || n != int64(before.FileSizeLow) || hex.EncodeToString(hash.Sum(nil)) != wintun.DLLSHA256 {
		return nil, errors.New("WINTUN_OFFICIAL_HASH_MISMATCH")
	}
	if _, err = p.file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if err = verifyWintunAuthenticode(path, h); err != nil {
		return nil, err
	}
	after, err := wintunHandleInfo(h, false)
	if err != nil || !wintunSameFile(before, after) {
		return nil, errors.New("WINTUN_FILE_CHANGED")
	}
	if l != nil {
		l.Printf("official Wintun signature=Valid publisher=WireGuard LLC verifier=WinVerifyTrust held_file=true official_hash=true")
	}
	failed = false
	return p, nil
}

func pinWintunFile(path string) (*verifiedWintunLease, error) {
	parts, err := wintunLocalPathParts(path)
	if err != nil {
		return nil, err
	}
	root, err := windows.UTF16PtrFromString(path[:3])
	if err != nil || windows.GetDriveType(root) != windows.DRIVE_FIXED {
		return nil, errors.New("WINTUN_LOCAL_DRIVE_REQUIRED")
	}
	p := &verifiedWintunLease{}
	failed := true
	defer func() {
		if failed {
			_ = p.Close()
		}
	}()
	current := path[:3]
	for i := 0; i < len(parts); i++ {
		name, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return nil, err
		}
		// Deny write as well as delete: a writable directory handle could turn
		// an ancestor into a reparse point without renaming the pinned DLL.
		h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return nil, fmt.Errorf("WINTUN_ANCESTOR_UNAVAILABLE: %w", err)
		}
		p.ancestors = append(p.ancestors, h)
		if _, err = wintunHandleInfo(h, true); err != nil {
			return nil, err
		}
		if i < len(parts)-1 {
			current = strings.TrimSuffix(current, "\\") + "\\" + parts[i]
		}
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("WINTUN_FILE_UNAVAILABLE: %w", err)
	}
	p.file = os.NewFile(uintptr(h), "verified-wintun.dll")
	if p.file == nil {
		_ = windows.CloseHandle(h)
		return nil, errors.New("WINTUN_FILE_HANDLE_INVALID")
	}
	if _, err = wintunHandleInfo(h, false); err != nil {
		return nil, err
	}
	failed = false
	return p, nil
}

func wintunHandleInfo(h windows.Handle, directory bool) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return info, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return info, errors.New("WINTUN_REPARSE_OR_TYPE_INVALID")
	}
	if !directory && (info.NumberOfLinks != 1 || info.FileSizeHigh != 0 || info.FileSizeLow == 0 || info.FileSizeLow > 16*1024*1024) {
		return info, errors.New("WINTUN_FILE_METADATA_INVALID")
	}
	return info, nil
}

func wintunSameFile(a, b windows.ByHandleFileInformation) bool {
	return a.VolumeSerialNumber == b.VolumeSerialNumber && a.FileIndexHigh == b.FileIndexHigh && a.FileIndexLow == b.FileIndexLow && a.FileSizeHigh == b.FileSizeHigh && a.FileSizeLow == b.FileSizeLow && a.CreationTime == b.CreationTime && a.LastWriteTime == b.LastWriteTime && a.FileAttributes == b.FileAttributes && a.NumberOfLinks == b.NumberOfLinks
}

func verifyWintunAuthenticode(path string, h windows.Handle) (err error) {
	for _, proc := range []*windows.LazyProc{wintunProviderData, wintunProviderSigner, wintunProviderCert, wintunCopyNative} {
		if err := proc.Find(); err != nil {
			return fmt.Errorf("WINTUN_TRUST_API_UNAVAILABLE: %w", err)
		}
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	file := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: name, File: h}
	// Default revocation/provider flags match PowerShell's WinTrust verification;
	// no offline/cache-only, trust bypass, or machine policy change is applied.
	data := windows.WinTrustData{Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE, UnionChoice: windows.WTD_CHOICE_FILE, FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&file), StateAction: windows.WTD_STATEACTION_VERIFY}
	defer func() {
		data.StateAction = windows.WTD_STATEACTION_CLOSE
		closeErr := windows.WinVerifyTrustEx(0, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
		if err == nil && closeErr != nil {
			err = fmt.Errorf("WINTUN_TRUST_STATE_CLOSE_FAILED: %w", closeErr)
		}
		runtime.KeepAlive(file)
		runtime.KeepAlive(name)
	}()
	if err = windows.WinVerifyTrustEx(0, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data); err != nil {
		return fmt.Errorf("WINTUN_AUTHENTICODE_UNTRUSTED: %w", err)
	}
	if data.StateData == 0 {
		return errors.New("WINTUN_TRUST_STATE_MISSING")
	}
	provider, _, _ := wintunProviderData.Call(uintptr(data.StateData))
	if provider == 0 {
		return errors.New("WINTUN_TRUST_PROVIDER_MISSING")
	}
	signer, _, _ := wintunProviderSigner.Call(provider, 0, 0, 0)
	if signer == 0 {
		return errors.New("WINTUN_PRIMARY_SIGNER_MISSING")
	}
	certificate, _, _ := wintunProviderCert.Call(signer, 0)
	if certificate == 0 {
		return errors.New("WINTUN_PRIMARY_CERTIFICATE_MISSING")
	}
	// Copy documented native prefixes rather than treating syscall uintptrs as
	// Go-managed pointers. Provider certificate storage belongs to the WVT state.
	var prefix struct {
		Size uint32
		Cert uintptr
	}
	wintunCopyNative.Call(uintptr(unsafe.Pointer(&prefix)), certificate, unsafe.Sizeof(prefix))
	if prefix.Size < uint32(unsafe.Sizeof(prefix)) || prefix.Cert == 0 {
		return errors.New("WINTUN_PRIMARY_CERTIFICATE_INVALID")
	}
	var cert struct {
		Encoding uint32
		Encoded  uintptr
		Length   uint32
		Info     uintptr
		Store    uintptr
	}
	wintunCopyNative.Call(uintptr(unsafe.Pointer(&cert)), prefix.Cert, unsafe.Sizeof(cert))
	if cert.Encoded == 0 || cert.Length == 0 || cert.Length > 128*1024 {
		return errors.New("WINTUN_PRIMARY_CERTIFICATE_INVALID")
	}
	der := make([]byte, cert.Length)
	wintunCopyNative.Call(uintptr(unsafe.Pointer(&der[0])), cert.Encoded, uintptr(len(der)))
	runtime.KeepAlive(prefix)
	runtime.KeepAlive(cert)
	return wintunPublisherCertificate(der)
}
