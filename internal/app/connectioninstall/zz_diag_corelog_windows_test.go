//go:build windows && amd64

package connectioninstall

import (
	"encoding/binary"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TEMPORARY diagnostic; always fails to surface output on CI.
func TestZZDiagCoreLogRename(t *testing.T) {
	sd, _ := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	open := func(p string, access, share, creation uint32, dir bool) windows.Handle {
		flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.FILE_ATTRIBUTE_NORMAL)
		if dir {
			flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
		}
		h, e := windows.CreateFile(windows.StringToUTF16Ptr(p), access, share, &sa, creation, flags, 0)
		if e != nil {
			t.Fatal(p, e)
		}
		return h
	}
	rename := func(root windows.Handle, name string) []byte {
		n, _ := windows.UTF16FromString(name)
		n = n[:len(n)-1]
		b := make([]byte, 20+len(n)*2)
		binary.LittleEndian.PutUint64(b[8:16], uint64(root))
		binary.LittleEndian.PutUint32(b[16:20], uint32(len(n)*2))
		for i, v := range n {
			binary.LittleEndian.PutUint16(b[20+i*2:], v)
		}
		return b
	}
	nt := func(h windows.Handle, b []byte, class uint32) error {
		var iosb windows.IO_STATUS_BLOCK
		e := windows.NtSetInformationFile(h, &iosb, &b[0], uint32(len(b)), class)
		if s, ok := e.(windows.NTStatus); ok {
			return s.Errno()
		}
		return e
	}
	all := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	for _, c := range []struct {
		name            string
		fileShare       uint32
		dirShare        uint32
		useRoot, useEx  bool
		writeBeforeSync bool
	}{
		{"prod-nt-root", windows.FILE_SHARE_READ, windows.FILE_SHARE_READ, true, false, false},
		{"file-share-all", all, windows.FILE_SHARE_READ, true, false, false},
		{"dir-share-all", windows.FILE_SHARE_READ, all, true, false, false},
		{"both-share-all", all, all, true, false, false},
		{"no-root-fullpath", windows.FILE_SHARE_READ, windows.FILE_SHARE_READ, false, false, false},
		{"win32-ex-root", windows.FILE_SHARE_READ, windows.FILE_SHARE_READ, true, true, false},
	} {
		dir := filepath.Join(t.TempDir(), c.name)
		if e := windows.CreateDirectory(windows.StringToUTF16Ptr(dir), &sa); e != nil {
			t.Fatal(e)
		}
		d := open(dir, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.FILE_TRAVERSE, c.dirShare, windows.OPEN_EXISTING, true)
		f := open(filepath.Join(dir, "core.log"), windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE, c.fileShare, windows.CREATE_NEW, false)
		var e error
		switch {
		case c.useEx:
			b := rename(d, "core.previous.log")
			e = windows.SetFileInformationByHandle(f, 22, &b[0], uint32(len(b)))
		case c.useRoot:
			e = nt(f, rename(d, "core.previous.log"), windows.FileRenameInformation)
		default:
			e = nt(f, rename(0, `\??\`+filepath.Join(dir, "core.previous.log")), windows.FileRenameInformation)
		}
		t.Errorf("%s: rename err=%v", c.name, e)
		windows.CloseHandle(f)
		windows.CloseHandle(d)
	}
}
