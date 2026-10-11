//go:build windows && amd64

package connectioninstall

import (
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestCoreSelfPinIdentityRejectsReplacementAndLinks(t *testing.T) {
	base := windows.ByHandleFileInformation{VolumeSerialNumber: 7, FileIndexHigh: 2, FileIndexLow: 9, FileSizeHigh: 0, FileSizeLow: 4096, NumberOfLinks: 1}
	if !sameCoreSelfFile(base, base) {
		t.Fatal("same file rejected")
	}
	for _, change := range []func(*windows.ByHandleFileInformation){
		func(v *windows.ByHandleFileInformation) { v.VolumeSerialNumber++ },
		func(v *windows.ByHandleFileInformation) { v.FileIndexHigh++ },
		func(v *windows.ByHandleFileInformation) { v.FileIndexLow++ },
		func(v *windows.ByHandleFileInformation) { v.FileSizeHigh++ },
		func(v *windows.ByHandleFileInformation) { v.FileSizeLow++ },
		func(v *windows.ByHandleFileInformation) { v.NumberOfLinks = 2 },
	} {
		other := base
		change(&other)
		if sameCoreSelfFile(base, other) {
			t.Fatal("changed identity accepted")
		}
	}
}

func TestCoreSelfPinReadHandleDeniesWriterAndDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.exe")
	if e := os.WriteFile(path, make([]byte, 4096), 0600); e != nil {
		t.Fatal(e)
	}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(h)
	firstID, e := readCoreSelfFileID(h)
	if e != nil {
		t.Fatal(e)
	}
	for _, access := range []uint32{windows.GENERIC_WRITE, windows.DELETE} {
		attempt, e := windows.CreateFile(windows.StringToUTF16Ptr(path), access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
		if e == nil {
			windows.CloseHandle(attempt)
			t.Fatal("immutable handle allowed modification")
		}
		if e != windows.ERROR_SHARING_VIOLATION {
			t.Fatalf("unexpected write/delete failure %v", e)
		}
	}
	reader, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if e != nil {
		t.Fatal("fresh read failed", e)
	}
	readerID, e := readCoreSelfFileID(reader)
	if e != nil || readerID != firstID {
		t.Fatal("same source 128-bit identity changed", e)
	}
	windows.CloseHandle(reader)
}

func TestCoreSelfPinNeverOptimizesOtherTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidate.exe")
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i)
	}
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	if _, used, e := pinnedCoreSelfHash(path); used || e != nil {
		t.Fatal("foreign target used pin", e)
	}
	sum, e := fileHash(path)
	expected := sha256.Sum256(data)
	if e != nil || sum != hex.EncodeToString(expected[:]) {
		t.Fatal("ordinary target hash changed", e)
	}
}
