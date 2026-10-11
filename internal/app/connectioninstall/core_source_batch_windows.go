//go:build windows && amd64

package connectioninstall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/transport/parentlifetime"
)

// CoreSourceBatch holds only the actual currently installed SCM self/parent.
// It is a scoped lease, never a reusable foreign-target hash cache, and never
// registers in coreSelfPin. Intermediate rule reads use Refresh; callers must
// Complete after the entire batch before admitting services or readiness.
type CoreSourceBatch struct {
	pin          *coreSelfSourcePin
	binding      CoreServiceBinding
	process      windows.Handle
	pid          uint32
	creation     uint64
	verifyActual func() error
	ownProcess   bool
}

func PinCoreSourceBatchSelf() (*CoreSourceBatch, error) {
	exe, e := os.Executable()
	if e != nil {
		return nil, e
	}
	pid := windows.GetCurrentProcessId()
	h, e := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		return nil, e
	}
	v, e := pinCoreSourceBatch(exe, h, pid, func() error {
		if windows.GetCurrentProcessId() != pid {
			return fmt.Errorf("CORE_BATCH_SELF_CHANGED")
		}
		return nil
	})
	if e != nil {
		windows.CloseHandle(h)
		return nil, e
	}
	v.ownProcess = true
	return v, nil
}
func PinCoreSourceBatchParent(exe string, link parentlifetime.Link) (*CoreSourceBatch, error) {
	if e := link.Validate(); e != nil {
		return nil, e
	}
	return pinCoreSourceBatch(exe, link.Handle, link.PID, link.Validate)
}
func pinCoreSourceBatch(exe string, process windows.Handle, pid uint32, actual func() error) (*CoreSourceBatch, error) {
	b, e := CurrentCoreBinding()
	if e != nil || b.Executable != exe || actual == nil || actual() != nil || VerifyCoreServiceProcess(pid) != nil || VerifyCoreExecutable(exe) != nil {
		return nil, fmt.Errorf("CORE_BATCH_SOURCE_UNPROVEN")
	}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(exe), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(h), exe)
	if f == nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("CORE_BATCH_HANDLE_INVALID")
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	p := &coreSelfSourcePin{path: exe, file: f}
	if e = protectedCoreSelfIdentity(h, &p.identity); e != nil {
		return nil, e
	}
	if p.fileID, e = readCoreSelfFileID(h); e != nil {
		return nil, e
	}
	size := int64(uint64(p.identity.FileSizeHigh)<<32 | uint64(p.identity.FileSizeLow))
	if size < 1024 || size > 256*1024*1024 {
		return nil, fmt.Errorf("CORE_BATCH_SIZE_INVALID")
	}
	hash := sha256.New()
	n, e := io.Copy(hash, io.LimitReader(f, 256*1024*1024+1))
	if e != nil || n != size {
		return nil, fmt.Errorf("CORE_BATCH_HASH_FAILED")
	}
	p.sha = hex.EncodeToString(hash.Sum(nil))
	if p.sha != b.SHA256 {
		return nil, fmt.Errorf("CORE_BATCH_SOURCE_HASH_CHANGED")
	}
	v := &CoreSourceBatch{pin: p, binding: b, process: process, pid: pid, verifyActual: actual}
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(process, &created, &exited, &kernel, &user) != nil {
		return nil, fmt.Errorf("CORE_BATCH_CREATION_UNREADABLE")
	}
	v.creation = uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	if v.creation == 0 {
		return nil, fmt.Errorf("CORE_BATCH_CREATION_UNREADABLE")
	}
	if e = v.Complete(); e != nil {
		return nil, e
	}
	ok = true
	return v, nil
}
func (v *CoreSourceBatch) Close() error {
	if v == nil {
		return nil
	}
	var e error
	if v.pin != nil && v.pin.file != nil {
		e = v.pin.file.Close()
		v.pin = nil
	}
	if v.ownProcess && v.process != 0 {
		windows.CloseHandle(v.process)
		v.process = 0
	}
	return e
}
func (v *CoreSourceBatch) Refresh() error {
	if v == nil || v.pin == nil || v.process == 0 || v.verifyActual == nil || v.verifyActual() != nil {
		return fmt.Errorf("CORE_BATCH_OWNER_CHANGED")
	}
	if pid, e := windows.GetProcessId(v.process); e != nil || pid != v.pid {
		return fmt.Errorf("CORE_BATCH_PID_CHANGED")
	}
	state, e := windows.WaitForSingleObject(v.process, 0)
	if e != nil || state != uint32(windows.WAIT_TIMEOUT) {
		return fmt.Errorf("CORE_BATCH_PROCESS_EXITED")
	}
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(v.process, &created, &exited, &kernel, &user) != nil || uint64(created.HighDateTime)<<32|uint64(created.LowDateTime) != v.creation {
		return fmt.Errorf("CORE_BATCH_CREATION_CHANGED")
	}
	var path [32768]uint16
	size := uint32(len(path))
	if windows.QueryFullProcessImageName(v.process, 0, &path[0], &size) != nil || size == 0 || size >= uint32(len(path)) || !strings.EqualFold(windows.UTF16ToString(path[:size]), v.pin.path) {
		return fmt.Errorf("CORE_BATCH_PROCESS_SOURCE_CHANGED")
	}
	// Existing exact directory/marker/receipt/ACL/full 128-bit identity checks.
	if e = verifyCoreSelfPin(v.pin); e != nil {
		return e
	}
	var held windows.ByHandleFileInformation
	if e = protectedCoreSelfIdentity(windows.Handle(v.pin.file.Fd()), &held); e != nil || held.LastWriteTime != v.pin.identity.LastWriteTime {
		return fmt.Errorf("CORE_BATCH_LASTWRITE_CHANGED")
	}
	root, e := coreStateDirectory()
	if e != nil {
		return e
	}
	raw, e := coreProtectedRead(filepath.Join(root, coreBindingFile), false, true)
	if e != nil {
		return e
	}
	fresh, e := parseCoreBinding(raw)
	if e != nil || fresh != v.binding {
		return fmt.Errorf("CORE_BATCH_BINDING_CHANGED")
	}
	return nil
}
func (v *CoreSourceBatch) Complete() error {
	if e := v.Refresh(); e != nil {
		return e
	}
	if VerifyCoreServiceProcess(v.pid) != nil || VerifyCoreExecutable(v.pin.path) != nil {
		return fmt.Errorf("CORE_BATCH_COMPLETE_SOURCE_CHANGED")
	}
	fresh, e := CurrentCoreBinding()
	if e != nil || fresh != v.binding {
		return fmt.Errorf("CORE_BATCH_COMPLETE_BINDING_CHANGED")
	}
	return v.Refresh()
}

// BoundSourceObservation exposes only the identity already fully validated and
// held by this lease. The fresh lightweight read must still match it. It is a
// diagnostic observation, not an alternative source or readiness authority.
func (v *CoreSourceBatch) BoundSourceObservation() (pid uint32, creation uint64, sha256 string, err error) {
	if err = v.Refresh(); err != nil {
		return 0, 0, "", err
	}
	return v.pid, v.creation, v.pin.sha, nil
}
