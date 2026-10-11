//go:build !windows

package fileshare

import (
	"os"
	"path/filepath"
)

func sameFolder(a, b string) bool { return a == b }
func openShareRoot(p string) (*os.Root, error) {
	for n := p; ; n = filepath.Dir(n) {
		i, e := os.Lstat(n)
		if e != nil {
			return nil, e
		}
		if i.Mode()&os.ModeSymlink != 0 {
			return nil, os.ErrPermission
		}
		if filepath.Dir(n) == n {
			break
		}
	}
	return os.OpenRoot(p)
}
