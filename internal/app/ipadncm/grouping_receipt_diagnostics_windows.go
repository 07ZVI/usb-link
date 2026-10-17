//go:build windows && amd64

package ipadncm

import (
	"io"
	"os"
	"path/filepath"
)

func inspectGroupingReceiptDirectory(dir, root string) (d groupingReceiptDirectory) {
	d.Status = "STORE_UNPROVEN"
	if _, err := os.Lstat(dir); err != nil {
		switch {
		case os.IsNotExist(err):
			d.Status = "DIRECTORY_ABSENT"
		case os.IsPermission(err):
			d.Status = "DIRECTORY_ACCESS_DENIED"
		default:
			d.Status = "DIRECTORY_READ_FAILED"
		}
		return
	}
	if !networkOnlyDriverStoreProtected(dir) {
		return
	}
	f, err := os.Open(dir)
	if err != nil {
		d.Status = "DIRECTORY_READ_FAILED"
		return
	}
	defer f.Close()
	names, err := f.Readdirnames(129)
	if err != nil && err != io.EOF {
		d.Status = "DIRECTORY_READ_FAILED"
		return
	}
	return summarizeGroupingReceiptNames(names, root, func(name string) (groupingJournal, error) { return readConfiguredGrouping(filepath.Join(dir, name)) })
}
