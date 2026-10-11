//go:build !windows

package macconnection

import "os"

func safeRuntimeDirectory(path string) bool {
	i, e := os.Lstat(path)
	return e == nil && i.IsDir() && i.Mode()&os.ModeSymlink == 0
}
func safeExisting(path string) bool {
	i, e := os.Lstat(path)
	return e == nil && i.Mode().IsRegular() && i.Mode()&os.ModeSymlink == 0
}
