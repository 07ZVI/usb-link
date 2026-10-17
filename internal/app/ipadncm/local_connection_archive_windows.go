//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/buildinfo"
	"sync"
	"unsafe"
)

var connectionArchives = newConnectionArchiveController()
var connectionArchiveOnce sync.Once

func StartConnectionArchive(ctx context.Context, dir string) func() {
	stop := func() {}
	if buildinfo.LocalDiagnostics != "true" {
		return stop
	}
	connectionArchiveOnce.Do(func() {
		run, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			s, e := openConnectionArchiveStore(dir)
			if e != nil {
				connectionArchives.fail("ARCHIVE_STORE_UNAVAILABLE")
				close(done)
				return
			}
			connectionArchives.run(run, s, done)
		}()
		stop = func() { cancel(); <-done }
	})
	return stop
}
func RecordConnectionArchiveEvent(kind string, value any) {
	RecordConnectionArchiveEventAccepted(kind, value)
}

// True acknowledges queue admission only, not durable persistence.
func RecordConnectionArchiveEventAccepted(kind string, value any) bool {
	if buildinfo.LocalDiagnostics != "true" {
		return false
	}
	return connectionArchives.record(kind, value)
}
func RecordConnectionArchiveAttempt(attempt uint64) {
	if buildinfo.LocalDiagnostics == "true" {
		connectionArchives.attempt(attempt)
	}
}
func ConnectionArchiveDiagnostics() any {
	if buildinfo.LocalDiagnostics != "true" {
		return nil
	}
	return connectionArchives.diagnostics()
}
func ReadConnectionArchiveIndex() (ConnectionArchiveIndex, error) { return connectionArchives.index() }
func ReadConnectionArchiveChunk(id string, offset int64, length int, expectedSHA ...string) (ConnectionArchiveChunk, error) {
	return connectionArchives.chunk(id, offset, length, expectedSHA...)
}

type connectionArchiveWindowsStore struct {
	dir       string
	lease     windows.Handle
	directory windows.Handle
	identity  map[string]windows.ByHandleFileInformation
}

func openConnectionArchiveStore(dir string) (*connectionArchiveWindowsStore, error) {
	if !networkOnlyDriverStoreProtected(dir) {
		return nil, errors.New("ARCHIVE_DIRECTORY_UNPROVEN")
	}
	dp, e := windows.UTF16PtrFromString(dir)
	if e != nil {
		return nil, e
	}
	dh, e := windows.CreateFile(dp, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			windows.CloseHandle(dh)
		}
	}()
	if e = softwareTrustedHandle(dh, true); e != nil {
		return nil, e
	}
	sd, e := windows.SecurityDescriptorFromString(portablePropertyFileSDDL)
	if e != nil {
		return nil, e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, e := windows.UTF16PtrFromString(filepath.Join(dir, "connection-archive.lock"))
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	if e = softwareTrustedHandle(h, false); e != nil {
		windows.CloseHandle(h)
		return nil, e
	}
	success = true
	return &connectionArchiveWindowsStore{dir: dir, lease: h, directory: dh, identity: map[string]windows.ByHandleFileInformation{}}, nil
}
func (s *connectionArchiveWindowsStore) close() {
	windows.CloseHandle(s.lease)
	windows.CloseHandle(s.directory)
}
func (s *connectionArchiveWindowsStore) path(id string) string {
	return filepath.Join(s.dir, "connection-archive-"+id+".jsonl")
}
func (s *connectionArchiveWindowsStore) open(id string, access, creation uint32) (*os.File, error) {
	if !validConnectionArchiveID(id) || !networkOnlyDriverStoreProtected(s.dir) {
		return nil, errors.New("ARCHIVE_DIRECTORY_UNPROVEN")
	}
	sd, e := windows.SecurityDescriptorFromString(portablePropertyFileSDDL)
	if e != nil {
		return nil, e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, e := windows.UTF16PtrFromString(s.path(id))
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, access, windows.FILE_SHARE_READ, &sa, creation, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	if e = softwareTrustedHandle(h, false); e != nil {
		windows.CloseHandle(h)
		return nil, e
	}
	var info windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(h, &info); e != nil {
		windows.CloseHandle(h)
		return nil, e
	}
	if old, ok := s.identity[id]; ok && (old.VolumeSerialNumber != info.VolumeSerialNumber || old.FileIndexHigh != info.FileIndexHigh || old.FileIndexLow != info.FileIndexLow) {
		windows.CloseHandle(h)
		return nil, errors.New("ARCHIVE_FILE_CHANGED")
	}
	s.identity[id] = info
	return os.NewFile(uintptr(h), s.path(id)), nil
}
func (s *connectionArchiveWindowsStore) load() (map[string][]byte, uint64, error) {
	entries, e := os.ReadDir(s.dir)
	if e != nil {
		return nil, 0, e
	}
	out := map[string][]byte{}
	unknown := uint64(0)
	for _, v := range entries {
		name := v.Name()
		if !strings.HasPrefix(name, "connection-archive-") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, "connection-archive-"), ".jsonl")
		if !validConnectionArchiveID(id) || name != "connection-archive-"+id+".jsonl" || v.IsDir() || len(out) >= 64 {
			unknown++
			continue
		}
		f, e := s.open(id, windows.GENERIC_READ, windows.OPEN_EXISTING)
		if e != nil {
			unknown++
			continue
		}
		b, e := io.ReadAll(io.LimitReader(f, connectionArchiveLimit+1))
		f.Close()
		if e != nil || len(b) > connectionArchiveLimit {
			unknown++
			continue
		}
		out[id] = b
	}
	return out, unknown, nil
}
func (s *connectionArchiveWindowsStore) appendArchiveBytes(id string, b []byte, create bool) error {
	mode := uint32(windows.OPEN_EXISTING)
	if create {
		mode = windows.CREATE_NEW
	}
	f, e := s.open(id, windows.GENERIC_WRITE, mode)
	if e != nil {
		return e
	}
	defer f.Close()
	n, e := f.Seek(0, io.SeekEnd)
	if e != nil {
		return e
	}
	if n+int64(len(b)) > connectionArchiveLimit {
		return errors.New("ARCHIVE_SIZE_LIMIT")
	}
	written, e := f.Write(b)
	if e != nil {
		return e
	}
	if written != len(b) {
		return io.ErrShortWrite
	}
	return f.Sync()
}
func (s *connectionArchiveWindowsStore) remove(id string) error {
	f, e := s.open(id, windows.DELETE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.OPEN_EXISTING)
	if e != nil {
		return e
	}
	defer f.Close()
	deleteFile := byte(1)
	r, _, e := windows.NewLazySystemDLL("kernel32.dll").NewProc("SetFileInformationByHandle").Call(f.Fd(), 4, uintptr(unsafe.Pointer(&deleteFile)), 1)
	if r == 0 {
		return e
	}
	delete(s.identity, id)
	return nil
}

func SetConnectionArchiveMaster(on bool) {
	connectionArchives.master(on && buildinfo.LocalDiagnostics == "true")
}
