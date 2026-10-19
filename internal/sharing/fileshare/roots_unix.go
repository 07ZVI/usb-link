//go:build !windows

package fileshare

import (
	"fmt"
	"golang.org/x/sys/unix"
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
