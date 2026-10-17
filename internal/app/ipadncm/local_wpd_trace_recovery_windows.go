//go:build windows && amd64

package ipadncm

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"unsafe"
)

var wpdControlTrace = windows.NewLazySystemDLL("advapi32.dll").NewProc("ControlTraceW")

// Windows amd64 WNODE_HEADER and EVENT_TRACE_PROPERTIES, including native
// alignment. No native event payload is represented by this control structure.
type wpdWnode struct {
	Size, Provider       uint32
	Historical           uint64
	Timestamp            int64
	GUID                 windows.GUID
	ClientContext, Flags uint32
}
type wpdTraceProperties struct {
	Wnode                                                                                                       wpdWnode
	BufferSize, MinimumBuffers, MaximumBuffers, MaximumFileSize, LogFileMode, FlushTimer, EnableFlags, AgeLimit uint32
	NumberOfBuffers, FreeBuffers, EventsLost, BuffersWritten, LogBuffersLost, RealTimeBuffersLost               uint32
	LoggerThreadID                                                                                              uintptr
	LogFileNameOffset, LoggerNameOffset                                                                         uint32
}
type wpdTracePropertyBuffer struct {
	Properties wpdTraceProperties
	Name       [1024]uint16
	Path       [1024]uint16
}

func wpdProperties(j localWPDTraceJournal, path string) (*wpdTracePropertyBuffer, error) {
	guid, e := windows.GUIDFromString(j.GUID)
	if e != nil {
		return nil, wpdTraceError("WPD_TRACE_JOURNAL_INVALID", 0)
	}
	b := new(wpdTracePropertyBuffer)
	b.Properties.Wnode.Size = uint32(unsafe.Sizeof(*b))
	b.Properties.Wnode.GUID = guid
	b.Properties.Wnode.Flags = 0x20000
	b.Properties.Wnode.ClientContext = 1
	b.Properties.LoggerNameOffset = uint32(unsafe.Offsetof(b.Name))
	if j.Schema == 1 {
		b.Properties.LogFileNameOffset = uint32(unsafe.Offsetof(b.Path))
	} else {
		path = ""
	}
	name, e := windows.UTF16FromString(j.Session)
	if e != nil || len(name) > len(b.Name) {
		return nil, wpdTraceError("WPD_TRACE_NAME_INVALID", 0)
	}
	file, e := windows.UTF16FromString(path)
	if e != nil || len(file) > len(b.Path) {
		return nil, wpdTraceError("WPD_TRACE_PATH_INVALID", 0)
	}
	copy(b.Name[:], name)
	copy(b.Path[:], file)
	return b, nil
}

// Query offsets reserve output capacity, not a request to enable file logging.
// Keep creation properties separate: metadata StartTrace still has offset zero.
func wpdQueryProperties(j localWPDTraceJournal) (*wpdTracePropertyBuffer, error) {
	b, e := wpdProperties(j, "")
	if e != nil {
		return nil, e
	}
	b.Name = [1024]uint16{}
	b.Path = [1024]uint16{}
	b.Properties.LogFileNameOffset = uint32(unsafe.Offsetof(b.Path))
	return b, nil
}

func queryLocalWPDTrace(j localWPDTraceJournal, path string) (*wpdTracePropertyBuffer, bool, error) {
	b, e := wpdQueryProperties(j)
	if e != nil {
		return nil, false, e
	}
	namePtr, _ := windows.UTF16PtrFromString(j.Session)
	r, _, _ := wpdControlTrace.Call(0, uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(b)), 0)
	if r == 4201 {
		return nil, false, nil
	}
	if r != 0 {
		return nil, false, wpdTraceError("WPD_TRACE_QUERY_FAILED", uint32(r))
	}
	guid, _ := windows.GUIDFromString(j.GUID)
	raw := unsafe.Slice((*byte)(unsafe.Pointer(b)), int(unsafe.Sizeof(*b)))
	evidence := wpdCheckSessionQuery(j, path, raw, b.Properties.Wnode.GUID == guid,
		b.Properties.LogFileMode, b.Properties.MaximumFileSize, b.Properties.LoggerNameOffset, b.Properties.LogFileNameOffset)
	if evidence.Mismatch != 0 {
		return nil, false, &localWPDTraceFailure{Code: "WPD_TRACE_SESSION_NOT_OWNED", Ownership: &evidence}
	}
	return b, true, nil
}
func restoreLocalWPDTraceLocked(dir string, lease windows.Handle) error {
	j, e := readLocalWPDTraceJournal(dir)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return wpdTraceError("WPD_TRACE_JOURNAL_UNPROVEN", wpdNativeCode(e))
	}
	if j.Stopped && j.Schema == 1 {
		return nil
	}
	path := ""
	if j.Schema == 1 {
		path = filepath.Join(dir, j.File)
	}
	b, found, e := queryLocalWPDTrace(j, path)
	if e != nil {
		return e
	}
	if found {
		if j.Stopped {
			return wpdTraceError("WPD_TRACE_STOP_UNCONFIRMED", 0)
		}
		// The random session GUID is supplied again. A same-name foreign session
		// with another GUID is rejected before any stop request.
		namePtr, _ := windows.UTF16PtrFromString(j.Session)
		r, _, _ := wpdControlTrace.Call(0, uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(b)), 1)
		if r != 0 && r != 4201 {
			return wpdTraceError("WPD_TRACE_STOP_FAILED", uint32(r))
		}
		if _, active, e := queryLocalWPDTrace(j, path); e != nil {
			return e
		} else if active {
			return wpdTraceError("WPD_TRACE_STOP_UNCONFIRMED", 0)
		}
	}
	return completeWPDTraceRecovery(j, true, func(done localWPDTraceJournal) error {
		return writeLocalWPDTraceJournal(dir, done)
	}, func(done localWPDTraceJournal) error {
		return removeCompletedWPDMetadataJournal(dir, lease, done)
	})
}
func RestoreLocalWPDTrace(dir string) error {
	lease, e := openLocalWPDTraceLease(dir)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(lease)
	return restoreLocalWPDTraceLocked(dir, lease)
}
