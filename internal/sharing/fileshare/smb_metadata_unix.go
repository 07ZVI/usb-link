//go:build !windows

package fileshare

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"suhang/usbnet/internal/sharing/smbcore/vfs"
	"time"
)

func smbDirectoryOpenFlags(bool) int { return os.O_RDONLY }

func smbDiskSpace(p string) (key string, total, free uint64, err error) {
	var st unix.Statfs_t
	if err = unix.Statfs(p, &st); err != nil {
		return
	}
	key = fmt.Sprint(st.Fsid)
	total = uint64(st.Blocks) * uint64(st.Bsize)
	free = uint64(st.Bavail) * uint64(st.Bsize)
	return
}

func smbSetFileTimes(f *os.File, _ *vfs.SetInfoRequest, atime, mtime time.Time) error {
	if err := singleLink(f); err != nil {
		return err
	}
	return unix.Futimes(int(f.Fd()), []unix.Timeval{unix.NsecToTimeval(atime.UnixNano()), unix.NsecToTimeval(mtime.UnixNano())})
}

func smbLockFile(f *os.File, offset, length uint64, exclusive, unlock bool) error {
	kind := int16(unix.F_RDLCK)
	if exclusive {
		kind = unix.F_WRLCK
	}
	if unlock {
		kind = unix.F_UNLCK
	}
	lock := unix.Flock_t{Type: kind, Whence: 0, Start: int64(offset), Len: int64(length)}
	return unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lock)
}

func smbRemoveOpened(_ *os.File, root *os.Root, sub string) error {
	// POSIX has no unlink-by-handle. The caller checked identity under the catalog
	// lock. Production SMB file sharing runs on Windows, using handle disposition.
	return root.Remove(sub)
}

func smbSetDirectoryTimes(f *os.File, info *vfs.SetInfoRequest, atime, mtime time.Time) error {
	return smbSetFileTimes(f, info, atime, mtime)
}

func smbRenameOpened(_ *os.File, root *os.Root, source, target string, _ bool) error {
	return root.Rename(source, target)
}

func shareRootIdentity(root *os.Root) (string, error) {
	f, e := root.Open(".")
	if e != nil {
		return "", e
	}
	defer f.Close()
	var info unix.Stat_t
	if e = unix.Fstat(int(f.Fd()), &info); e != nil {
		return "", e
	}
	return fmt.Sprintf("unix:%016x:%016x", uint64(info.Dev), uint64(info.Ino)), nil
}
