//go:build windows

package fileshare

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
)

func sameFolder(a, b string) bool { return strings.EqualFold(a, b) }
func openShareRoot(p string) (*os.Root, error) {
	if !IsVolumePath(p) && (len(p) < 3 || p[1] != ':' || p[2] != '\\' || strings.Contains(p[2:], ":") || strings.ContainsAny(p, "\x00\r\n")) {
		return nil, os.ErrPermission
	}
	for n := p; ; n = filepath.Dir(n) {
		a, e := windows.GetFileAttributes(windows.StringToUTF16Ptr(n))
		if e != nil {
			return nil, e
		}
		if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return nil, os.ErrPermission
		}
		if filepath.Dir(n) == n {
			break
		}
	}
	root, e := os.OpenRoot(p)
	if e != nil {
		return nil, e
	}
	// os.OpenRoot omits FILE_SHARE_DELETE, so the pinned handle would stop the
	// shared folder from being renamed or moved. Root.OpenRoot shares DELETE.
	shared, e := root.OpenRoot(".")
	root.Close()
	return shared, e
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

// Resolve from the same validated directory handle used to check identity.
func StableVolumePath(path, identity string) (string, error) {
	root, err := openShareRoot(path)
	if err != nil {
		return "", err
	}
	defer root.Close()
	actual, err := shareRootIdentity(root)
	if err != nil {
		return "", err
	}
	if identity == "" || identity != actual {
		return "", fmt.Errorf("SHARE_ROOT_IDENTITY_CHANGED")
	}
	f, err := root.Open(".")
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(f.Fd()), &buf[0], uint32(len(buf)), 1 /* VOLUME_NAME_GUID */)
	if err != nil {
		return "", err
	}
	if n == 0 || n > 4096 || n >= uint32(len(buf)) {
		return "", fmt.Errorf("SHARE_VOLUME_PATH_INVALID")
	}
	result := windows.UTF16ToString(buf[:n])
	// Some APIs omit the trailing slash of a volume root.
	if len(result) == 48 {
		result += `\`
	}
	if !IsVolumePath(result) {
		return "", fmt.Errorf("SHARE_VOLUME_PATH_INVALID")
	}
	return result, nil
}

// Presentation only: never use the current drive letter to access the share.
func DisplayVolumePath(path string) string {
	root := VolumeRoot(path)
	if root == "" {
		return path
	}
	buf := make([]uint16, 32768)
	var size uint32
	if windows.GetVolumePathNamesForVolumeName(windows.StringToUTF16Ptr(root), &buf[0], uint32(len(buf)), &size) == nil {
		for pos := 0; pos < len(buf) && buf[pos] != 0; {
			end := pos
			for end < len(buf) && buf[end] != 0 {
				end++
			}
			mount := windows.UTF16ToString(buf[pos:end])
			if len(mount) == 3 && mount[1] == ':' {
				return mount + path[len(root):]
			}
			pos = end + 1
		}
	}
	return "已綁定磁碟 · " + path[len(root):]
}
