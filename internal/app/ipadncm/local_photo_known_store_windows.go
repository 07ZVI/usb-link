//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
)

// Same protected store, ACL and write-through discipline as the journal.
func readLocalPhotoKnown(dir string) (localPhotoKnown, error) {
	empty := localPhotoKnown{Schema: 1}
	if !networkOnlyDriverStoreProtected(dir) {
		return empty, errors.New("PHOTO_STORE_UNPROVEN")
	}
	b, e := readPortableProtectedFile(filepath.Join(dir, localPhotoKnownFile), localPhotoKnownLimit)
	if os.IsNotExist(e) {
		return empty, nil
	}
	if e != nil {
		return empty, e
	}
	return decodeLocalPhotoKnown(b)
}
func writeLocalPhotoKnown(dir string, k localPhotoKnown) error {
	if !k.valid() || !networkOnlyDriverStoreProtected(dir) {
		return errors.New("PHOTO_STORE_UNPROVEN")
	}
	path := filepath.Join(dir, localPhotoKnownFile)
	if _, e := readLocalPhotoKnown(dir); e != nil {
		return e
	}
	b, e := json.Marshal(k)
	if e != nil || len(b) > localPhotoKnownLimit {
		return errors.New("PHOTO_JOURNAL_LIMIT")
	}
	f, temp, e := createPortableProtectedTemp(dir)
	if e != nil {
		return e
	}
	defer os.Remove(temp)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	rb, e := readPortableProtectedFile(temp, localPhotoKnownLimit)
	if e != nil || !bytes.Equal(rb, b) {
		return errors.New("PHOTO_JOURNAL_READBACK_FAILED")
	}
	if !networkOnlyDriverStoreProtected(dir) {
		return errors.New("PHOTO_STORE_CHANGED")
	}
	if e = windows.MoveFileEx(windows.StringToUTF16Ptr(temp), windows.StringToUTF16Ptr(path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return e
	}
	rb, e = readPortableProtectedFile(path, localPhotoKnownLimit)
	if e != nil || !bytes.Equal(rb, b) {
		return errors.New("PHOTO_JOURNAL_READBACK_FAILED")
	}
	_, e = decodeLocalPhotoKnown(rb)
	return e
}

// Only uninstall retires the remembered identities, after a verified restore.
func removeLocalPhotoKnown(dir string) error {
	if _, e := readLocalPhotoKnown(dir); e != nil {
		return e
	}
	if e := os.Remove(filepath.Join(dir, localPhotoKnownFile)); e != nil && !os.IsNotExist(e) {
		return e
	}
	return nil
}
