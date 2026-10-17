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

func readLocalPhotoJournal(dir string) (localPhotoJournal, error) {
	empty := localPhotoJournal{Schema: 1}
	if !networkOnlyDriverStoreProtected(dir) {
		return empty, errors.New("PHOTO_STORE_UNPROVEN")
	}
	b, e := readPortableProtectedFile(filepath.Join(dir, localPhotoJournalFile), localPhotoJournalLimit)
	if os.IsNotExist(e) {
		return empty, nil
	}
	if e != nil {
		return empty, e
	}
	return decodeLocalPhotoJournal(b)
}
func writeLocalPhotoJournal(dir string, j localPhotoJournal) error {
	if !j.valid() || !networkOnlyDriverStoreProtected(dir) {
		return errors.New("PHOTO_STORE_UNPROVEN")
	}
	path := filepath.Join(dir, localPhotoJournalFile)
	if _, e := readLocalPhotoJournal(dir); e != nil {
		return e
	}
	b, e := json.Marshal(j)
	if e != nil || len(b) > localPhotoJournalLimit {
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
	rb, e := readPortableProtectedFile(temp, localPhotoJournalLimit)
	if e != nil || !bytes.Equal(rb, b) {
		return errors.New("PHOTO_JOURNAL_READBACK_FAILED")
	}
	if !networkOnlyDriverStoreProtected(dir) {
		return errors.New("PHOTO_STORE_CHANGED")
	}
	if e = windows.MoveFileEx(windows.StringToUTF16Ptr(temp), windows.StringToUTF16Ptr(path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return e
	}
	rb, e = readPortableProtectedFile(path, localPhotoJournalLimit)
	if e != nil || !bytes.Equal(rb, b) {
		return errors.New("PHOTO_JOURNAL_READBACK_FAILED")
	}
	_, e = decodeLocalPhotoJournal(rb)
	return e
}
func verifyLocalPhotoOwned(dir string, p portablePropertyOriginal) error {
	j, e := readLocalPhotoJournal(dir)
	if e != nil {
		return e
	}
	for _, v := range j.Entries {
		if v == p {
			return nil
		}
	}
	return errors.New("PHOTO_JOURNAL_OWNERSHIP_CHANGED")
}
