//go:build windows

package fileshare

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
)

func sameFolder(a, b string) bool { return strings.EqualFold(a, b) }
func openShareRoot(p string) (*os.Root, error) {
	if len(p) < 3 || p[1] != ':' || p[2] != '\\' || strings.Contains(p[2:], ":") || strings.ContainsAny(p, "\x00\r\n") {
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
