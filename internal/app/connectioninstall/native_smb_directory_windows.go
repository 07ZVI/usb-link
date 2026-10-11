//go:build windows && amd64

package connectioninstall

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// An empty relative name opens the pinned directory itself, including a volume
// root. No second pathname lookup, file creation, backup intent or privilege
// adjustment is involved. ReOpenFile unconditionally rejects directories on
// native Windows, even when FILE_FLAG_BACKUP_SEMANTICS is supplied.
func reopenSMBDirectory(pin windows.Handle, access uint32) (windows.Handle, error) {
	name, err := windows.NewNTUnicodeString("")
	if err != nil {
		return windows.InvalidHandle, err
	}
	oa := windows.OBJECT_ATTRIBUTES{
		RootDirectory: pin,
		ObjectName:    name,
		Attributes:    windows.OBJ_DONT_REPARSE,
	}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	err = windows.NtCreateFile(&h, access, &oa, &windows.IO_STATUS_BLOCK{}, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	runtime.KeepAlive(name)
	if err != nil {
		var status windows.NTStatus
		if errors.As(err, &status) {
			return windows.InvalidHandle, status.Errno()
		}
		return windows.InvalidHandle, err
	}
	return h, nil
}
