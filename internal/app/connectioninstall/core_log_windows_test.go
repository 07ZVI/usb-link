//go:build windows && amd64

package connectioninstall

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestNativeCoreLogRotationUsesExactPrivateHandles(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("private BA/SY log requires administrator token")
	}
	sd, e := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if e != nil {
		t.Fatal(e)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	path := filepath.Join(t.TempDir(), "isolated-log")
	if e = windows.CreateDirectory(windows.StringToUTF16Ptr(path), &sa); e != nil {
		t.Fatal(e)
	}
	dir, e := coreLogOpen(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.FILE_TRAVERSE, windows.OPEN_EXISTING, nil, true, 0)
	if e != nil {
		t.Fatal(e)
	}
	f, e := coreLogOpen(filepath.Join(path, coreLogCurrent), windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE, windows.CREATE_NEW, &sa, false, coreLogLimit)
	if e != nil {
		dir.Close()
		t.Fatal(e)
	}
	w := &coreLogWriter{dir: dir, file: f, path: path, sa: sa}
	defer w.Close()
	for i := 0; i < 150; i++ {
		event := bytes.Repeat([]byte{byte('a' + i%26)}, coreLogEventLimit)
		if n, e := w.Write(event); e != nil || n != len(event) {
			t.Fatalf("write %d n=%d error=%v", i, n, e)
		}
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{coreLogCurrent, coreLogPrevious} {
		info, e := os.Stat(filepath.Join(path, name))
		if e != nil || info.Size() > coreLogLimit {
			t.Fatalf("unbounded/missing %s: %v", name, e)
		}
	}
	entries, e := os.ReadDir(path)
	if e != nil || len(entries) != 2 {
		t.Fatalf("unexpected files %v %v", entries, e)
	}
	if _, e = w.Write([]byte("closed")); e == nil {
		t.Fatal("closed log accepted")
	}
}
