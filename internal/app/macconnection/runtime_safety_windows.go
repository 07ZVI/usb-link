//go:build windows && amd64

package macconnection

import "golang.org/x/sys/windows"

func safeRuntimeDirectory(path string) bool {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return false
	}
	a, e := windows.GetFileAttributes(p)
	return e == nil && a&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 && a&windows.FILE_ATTRIBUTE_DIRECTORY != 0
}
