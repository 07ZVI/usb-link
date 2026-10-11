//go:build windows

package fileshare

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/sharing/smbcore/vfs"
	"time"
	"unsafe"
)

// os.Root treats O_RDWR as a non-directory open on Windows. Keep enumeration
// handles read-only; reopen the existing handle for directory metadata access.
func smbDirectoryOpenFlags(bool) int { return os.O_RDONLY }

func smbDiskSpace(p string) (key string, total, free uint64, err error) {
	path, e := windows.UTF16PtrFromString(p)
	if e != nil {
		err = e
		return
	}
	volume := make([]uint16, 32768)
	if err = windows.GetVolumePathName(path, &volume[0], uint32(len(volume))); err != nil {
		return
	}
	key = windows.UTF16ToString(volume)
	var allFree uint64
	err = windows.GetDiskFreeSpaceEx(path, &free, &total, &allFree)
	return
}

// FileRenameInformation takes a pinned destination directory and the opened
// source handle. ReplaceIfExists=false is checked atomically by Windows.
func smbRenameOpened(f *os.File, root *os.Root, _, target string, replace bool) error {
	parent, e := root.Open(filepath.Dir(target))
	if e != nil {
		return e
	}
	defer parent.Close()
	h, e := smbReopenHandle(f, windows.DELETE|windows.SYNCHRONIZE)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	name := filepath.Base(target)
	encoded, e := windows.UTF16FromString(name)
	if e != nil {
		return e
	}
	type renameInfo struct {
		ReplaceIfExists byte
		RootDirectory   windows.Handle
		FileNameLength  uint32
		FileName        [1]uint16
	}
	var dummy renameInfo
	nameOffset := int(unsafe.Offsetof(dummy.FileName))
	buf := make([]byte, max(int(unsafe.Sizeof(dummy)), nameOffset+(len(encoded)-1)*2))
	info := (*renameInfo)(unsafe.Pointer(&buf[0]))
	if replace {
		info.ReplaceIfExists = 1
	}
	info.RootDirectory = windows.Handle(parent.Fd())
	info.FileNameLength = uint32((len(encoded) - 1) * 2)
	for i, ch := range encoded[:len(encoded)-1] {
		binary.LittleEndian.PutUint16(buf[nameOffset+2*i:], ch)
	}
	var iosb windows.IO_STATUS_BLOCK
	e = windows.NtSetInformationFile(h, &iosb, &buf[0], uint32(len(buf)), windows.FileRenameInformation)
	if status, ok := e.(windows.NTStatus); ok {
		return status.Errno()
	}
	return e
}

func smbSetFileTimes(f *os.File, info *vfs.SetInfoRequest, atime, mtime time.Time) error {
	if err := singleLink(f); err != nil {
		return err
	}
	handle := windows.Handle(f.Fd())
	a, w := windows.NsecToFiletime(atime.UnixNano()), windows.NsecToFiletime(mtime.UnixNano())
	var created *windows.Filetime
	if info.CreationTime != nil {
		c := windows.NsecToFiletime(info.CreationTime.UnixNano())
		created = &c
	}
	return windows.SetFileTime(handle, created, &a, &w)
}

func smbLockFile(f *os.File, offset, length uint64, exclusive, unlock bool) error {
	overlapped := windows.Overlapped{Offset: uint32(offset), OffsetHigh: uint32(offset >> 32)}
	if unlock {
		return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, uint32(length), uint32(length>>32), &overlapped)
	}
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	return windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, uint32(length), uint32(length>>32), &overlapped)
}

var smbReOpenFile = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")

func smbReopenHandle(f *os.File, access uint32) (windows.Handle, error) {
	if e := smbReOpenFile.Find(); e != nil {
		return windows.InvalidHandle, e
	}
	h, _, e := smbReOpenFile.Call(f.Fd(), uintptr(access), windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_FLAG_BACKUP_SEMANTICS)
	if windows.Handle(h) == windows.InvalidHandle {
		return windows.InvalidHandle, e
	}
	return windows.Handle(h), nil
}

// Reopen the existing handle with DELETE access; no second pathname lookup can
// switch this operation to a replacement file. Root.OpenFile shares DELETE.
func smbRemoveOpened(f *os.File, _ *os.Root, _ string) error {
	h, e := smbReopenHandle(f, windows.DELETE)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	disposition := byte(1)
	return windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, (*byte)(unsafe.Pointer(&disposition)), 1)
}

func smbSetDirectoryTimes(f *os.File, info *vfs.SetInfoRequest, atime, mtime time.Time) error {
	h, e := smbReopenHandle(f, windows.FILE_WRITE_ATTRIBUTES)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	a, w := windows.NsecToFiletime(atime.UnixNano()), windows.NsecToFiletime(mtime.UnixNano())
	var created *windows.Filetime
	if info.CreationTime != nil {
		c := windows.NsecToFiletime(info.CreationTime.UnixNano())
		created = &c
	}
	return windows.SetFileTime(h, created, &a, &w)
}

// Capture volume and file IDs from a handle, before releasing it; pathname
// FileInfo on Windows may otherwise defer its identity query until comparison.
func shareRootIdentity(root *os.Root) (string, error) {
	f, e := root.Open(".")
	if e != nil {
		return "", e
	}
	defer f.Close()
	var info windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); e != nil {
		return "", e
	}
	return fmt.Sprintf("win:%08x:%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}
