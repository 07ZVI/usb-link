//go:build !windows

package fileshare

import (
	"os"
	"syscall"
)

func singleLink(f *os.File) error {
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && info.Mode().IsRegular() && st.Nlink > 1 {
		return os.ErrPermission
	}
	return nil
}
