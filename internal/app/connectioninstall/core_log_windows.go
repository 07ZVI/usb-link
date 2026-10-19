//go:build windows && amd64

package connectioninstall

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/diagnostics/coreterm"
)

const coreLogDirectory = "USBLink-Core-7c494949-9688-4bd4-90c6-257e315f9550"
const coreLogMarker = "core-log-product.txt"
const coreLogCurrent = "core.log"
const coreLogPrevious = "core.previous.log"

func coreLogSecurity(h windows.Handle, directory bool, limit uint64) error {
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || !directory && (info.NumberOfLinks != 1 || uint64(info.FileSizeHigh)<<32|uint64(info.FileSizeLow) > limit) {
		return fmt.Errorf("CORE_LOG_FILE_IDENTITY_UNPROVEN")
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || !coreFileACLValid(sd) {
		return fmt.Errorf("CORE_LOG_FILE_SECURITY_UNPROVEN")
	}
	control, _, e := sd.Control()
	acl, _, ae := sd.DACL()
	if e != nil || ae != nil || control&windows.SE_DACL_PROTECTED == 0 || acl.AceCount != 2 {
		return fmt.Errorf("CORE_LOG_PRIVATE_ACL_REQUIRED")
	}
	for i := uint32(0); i < 2; i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &a) != nil || a == nil || uint32(a.Mask) != 0x001f01ff {
			return fmt.Errorf("CORE_LOG_PRIVATE_ACL_REQUIRED")
		}
	}
	return nil
}

func coreLogOpen(path string, access, creation uint32, sa *windows.SecurityAttributes, directory bool, limit uint64) (*os.File, error) {
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.FILE_ATTRIBUTE_NORMAL)
	share := uint32(windows.FILE_SHARE_READ)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
		// A rename relative to this handle fails with a sharing violation unless
		// the directory handle itself allows FILE_SHARE_WRITE and FILE_SHARE_DELETE.
		share |= windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
	}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), access, share, sa, creation, flags, 0)
	if e != nil {
		return nil, e
	}
	if e = coreLogSecurity(h, directory, limit); e != nil {
		windows.CloseHandle(h)
		return nil, e
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("CORE_LOG_HANDLE_UNAVAILABLE")
	}
	return f, nil
}

// OpenCoreLog is optional diagnostics, never an ownership or readiness proof.
// It admits only an activated, unchanged SYSTEM core and one fixed protected
// ProgramData directory. Unknown files/security are preserved, not repaired.
func OpenCoreLog() (io.WriteCloser, string, error) {
	self, e := os.Executable()
	if e != nil {
		return nil, "", e
	}
	if _, e = ActivateCoreOwner(self); e != nil {
		return nil, "", e
	}
	base, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	volume := filepath.VolumeName(base)
	if e != nil || !filepath.IsAbs(base) || len(volume) != 2 || volume[1] != ':' || filepath.Clean(base) != base {
		return nil, "", fmt.Errorf("CORE_LOG_PROGRAM_DATA_UNPROVEN")
	}
	for p, depth := base, 0; ; p, depth = filepath.Dir(p), depth+1 {
		if depth > 32 || noReparse(p) != nil {
			return nil, "", fmt.Errorf("CORE_LOG_PROGRAM_DATA_UNPROVEN")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	path := filepath.Join(base, coreLogDirectory)
	sd, e := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if e != nil {
		return nil, "", e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	created := false
	e = windows.CreateDirectory(windows.StringToUTF16Ptr(path), &sa)
	if e == nil {
		created = true
	} else if e != windows.ERROR_ALREADY_EXISTS {
		return nil, "", e
	}
	dir, e := coreLogOpen(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.FILE_TRAVERSE, windows.OPEN_EXISTING, nil, true, 0)
	if e != nil {
		return nil, "", e
	}
	retained := false
	defer func() {
		if !retained {
			dir.Close()
		}
	}()
	markerPath := filepath.Join(path, coreLogMarker)
	if created {
		marker, e := coreLogOpen(markerPath, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.CREATE_NEW, &sa, false, 4096)
		if e != nil {
			return nil, "", e
		}
		_, e = marker.Write([]byte(ProductID + "\n"))
		if e == nil {
			e = marker.Sync()
		}
		e = errors.Join(e, marker.Close())
		if e != nil {
			return nil, "", e
		}
	}
	marker, e := coreLogOpen(markerPath, windows.GENERIC_READ, windows.OPEN_EXISTING, nil, false, 4096)
	if e != nil {
		return nil, "", e
	}
	b, e := io.ReadAll(io.LimitReader(marker, 4097))
	e = errors.Join(e, marker.Close())
	if e != nil || !bytes.Equal(b, []byte(ProductID+"\n")) {
		return nil, "", fmt.Errorf("CORE_LOG_PRODUCT_UNPROVEN")
	}
	previous, e := coreLogOpen(filepath.Join(path, coreLogPrevious), windows.GENERIC_READ, windows.OPEN_EXISTING, nil, false, coreLogLimit)
	if e == nil {
		if e = previous.Close(); e != nil {
			return nil, "", e
		}
	} else if e != windows.ERROR_FILE_NOT_FOUND {
		return nil, "", e
	}
	currentPath := filepath.Join(path, coreLogCurrent)
	f, e := coreLogOpen(currentPath, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE, windows.OPEN_ALWAYS, &sa, false, coreLogLimit)
	if e != nil {
		return nil, "", e
	}
	size, e := f.Seek(0, io.SeekEnd)
	if e != nil {
		f.Close()
		return nil, "", e
	}
	retained = true
	return &coreLogWriter{dir: dir, file: f, path: path, size: size, sa: sa}, currentPath, nil
}

type coreLogWriter struct {
	sync.Mutex
	dir, file *os.File
	path      string
	size      int64
	sa        windows.SecurityAttributes
	closed    bool
	err       error
}

func (w *coreLogWriter) rotate() error {
	if e := coreLogSecurity(windows.Handle(w.dir.Fd()), true, 0); e != nil {
		return e
	}
	if e := coreLogSecurity(windows.Handle(w.file.Fd()), false, coreLogLimit); e != nil {
		return e
	}
	previous, e := coreLogOpen(filepath.Join(w.path, coreLogPrevious), windows.GENERIC_READ|windows.DELETE, windows.OPEN_EXISTING, nil, false, coreLogLimit)
	if e == nil {
		remove := byte(1)
		e = windows.SetFileInformationByHandle(windows.Handle(previous.Fd()), windows.FileDispositionInfo, &remove, 1)
		e = errors.Join(e, previous.Close())
		if e != nil {
			return e
		}
	} else if e != windows.ERROR_FILE_NOT_FOUND {
		return e
	}
	if e = w.file.Sync(); e != nil {
		return e
	}
	name, _ := windows.UTF16FromString(coreLogPrevious)
	name = name[:len(name)-1]
	// FILE_RENAME_INFORMATION on amd64: replace BOOLEAN at 0, root HANDLE at 8,
	// filename byte length at 16, WCHAR filename at 20. No replace allowed.
	rename := make([]byte, 20+len(name)*2)
	binary.LittleEndian.PutUint64(rename[8:16], uint64(w.dir.Fd()))
	binary.LittleEndian.PutUint32(rename[16:20], uint32(len(name)*2))
	for i, v := range name {
		binary.LittleEndian.PutUint16(rename[20+i*2:], v)
	}
	// SetFileInformationByHandle rejects a RootDirectory rename (ERROR_INVALID_PARAMETER);
	// the native call keeps the exact-directory rename.
	var iosb windows.IO_STATUS_BLOCK
	if e = windows.NtSetInformationFile(windows.Handle(w.file.Fd()), &iosb, &rename[0], uint32(len(rename)), windows.FileRenameInformation); e != nil {
		if status, ok := e.(windows.NTStatus); ok {
			return status.Errno()
		}
		return e
	}
	if e = w.file.Close(); e != nil {
		return e
	}
	w.file = nil
	f, e := coreLogOpen(filepath.Join(w.path, coreLogCurrent), windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE, windows.CREATE_NEW, &w.sa, false, coreLogLimit)
	if e != nil {
		return e
	}
	w.file = f
	w.size = 0
	return nil
}
func (w *coreLogWriter) Write(b []byte) (int, error) {
	w.Lock()
	defer w.Unlock()
	if w.closed {
		return 0, os.ErrClosed
	}
	if w.err != nil {
		return 0, w.err
	}
	if len(b) == 0 {
		return 0, nil
	}
	message := coreLogMessage(b)
	rotate, e := coreLogRotation(w.size, len(message))
	if e == nil && rotate {
		e = w.rotate()
	}
	if e == nil {
		e = coreLogSecurity(windows.Handle(w.dir.Fd()), true, 0)
	}
	if e == nil {
		e = coreLogSecurity(windows.Handle(w.file.Fd()), false, coreLogLimit)
	}
	if e != nil {
		w.err = e
		return 0, e
	}
	n, e := w.file.Write(message)
	w.size += int64(n)
	if e == nil && n != len(message) {
		e = io.ErrShortWrite
	}
	if e != nil {
		w.err = e
		return 0, e
	}
	return len(b), nil
}
func (w *coreLogWriter) Close() error {
	w.Lock()
	defer w.Unlock()
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.file != nil {
		w.err = errors.Join(w.err, w.file.Sync(), w.file.Close())
		w.file = nil
	}
	w.err = errors.Join(w.err, w.dir.Close())
	return w.err
}

// CoreLogEvidence is read before OpenCoreLog holds the log, so the tail shows
// how the previous core ended. Bounded printable ASCII; evidence only.
func CoreLogEvidence() map[string]any {
	row := map[string]any{}
	base, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	dir := filepath.Join(base, coreLogDirectory)
	if e != nil || noReparse(dir) != nil {
		row["error"] = "CORE_LOG_DIRECTORY_UNAVAILABLE"
		return row
	}
	for key, leaf := range map[string]string{"current": coreLogCurrent, "previous": coreLogPrevious} {
		if size, text, ok := coreterm.Tail(filepath.Join(dir, leaf), 2048); ok {
			row[key+"_size"], row[key+"_tail"] = size, text
		} else {
			row[key+"_size"] = -1
		}
	}
	return row
}
