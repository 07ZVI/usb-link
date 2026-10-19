//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type usbTraceJournal struct {
	Schema  int
	Name    string
	GUID    string
	Stopped bool
}

const usbTraceJournalName = "local-usb-metadata-trace.json"

func (j usbTraceJournal) valid() bool {
	const prefix = "USBLink-USBMetadata-"
	g, e := windows.GUIDFromString(j.GUID)
	return j.Schema == 1 && e == nil && g != (windows.GUID{}) && strings.HasPrefix(j.Name, prefix) && len(j.Name) == len(prefix)+32 && strings.Trim(j.Name[len(prefix):], "0123456789abcdef") == ""
}
func usbTraceReadJournal(dir string) (usbTraceJournal, error) {
	var j usbTraceJournal
	if !networkOnlyDriverStoreProtected(dir) {
		return j, errors.New("USB_TRACE_STORE_UNPROVEN")
	}
	b, e := readPortableProtectedFile(filepath.Join(dir, usbTraceJournalName), 4096)
	if e != nil {
		return j, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&j) != nil || d.Decode(new(any)) != io.EOF || !j.valid() {
		return j, errors.New("USB_TRACE_JOURNAL_UNPROVEN")
	}
	return j, nil
}
func usbTraceWriteJournal(dir string, j usbTraceJournal) error {
	if !j.valid() || !networkOnlyDriverStoreProtected(dir) {
		return errors.New("USB_TRACE_STORE_UNPROVEN")
	}
	if _, e := usbTraceReadJournal(dir); e != nil && !os.IsNotExist(e) {
		return e
	}
	b, _ := json.Marshal(j)
	f, temp, e := createPortableProtectedTemp(dir)
	if e != nil {
		return errors.New("USB_TRACE_JOURNAL_WRITE_FAILED")
	}
	defer os.Remove(temp)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return errors.New("USB_TRACE_JOURNAL_WRITE_FAILED")
	}
	rb, e := readPortableProtectedFile(temp, 4096)
	if e != nil || !bytes.Equal(b, rb) || !networkOnlyDriverStoreProtected(dir) {
		return errors.New("USB_TRACE_JOURNAL_READBACK_FAILED")
	}
	if e = windows.MoveFileEx(windows.StringToUTF16Ptr(temp), windows.StringToUTF16Ptr(filepath.Join(dir, usbTraceJournalName)), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return errors.New("USB_TRACE_JOURNAL_WRITE_FAILED")
	}
	got, e := usbTraceReadJournal(dir)
	if e != nil || got != j {
		return errors.New("USB_TRACE_JOURNAL_READBACK_FAILED")
	}
	return nil
}
func usbTraceLease(dir string) (windows.Handle, error) {
	if !networkOnlyDriverStoreProtected(dir) {
		return 0, errors.New("USB_TRACE_STORE_UNPROVEN")
	}
	sd, e := windows.SecurityDescriptorFromString(portablePropertyFileSDDL)
	if e != nil {
		return 0, e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(filepath.Join(dir, "local-usb-metadata-trace.lock")), windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return 0, errors.New("USB_TRACE_OWNER_BUSY")
	}
	if softwareTrustedHandle(h, false) != nil {
		windows.CloseHandle(h)
		return 0, errors.New("USB_TRACE_STORE_UNPROVEN")
	}
	return h, nil
}

// QUERY offsets reserve output space; unlike StartTrace, they do not request
// a log file. Keep this buffer separate from the session creation properties.
func usbTraceQueryProperties(j usbTraceJournal) *wpdTracePropertyBuffer {
	b := new(wpdTracePropertyBuffer)
	b.Properties.Wnode.Size = uint32(unsafe.Sizeof(*b))
	b.Properties.Wnode.GUID, _ = windows.GUIDFromString(j.GUID)
	b.Properties.Wnode.Flags = 0x20000
	b.Properties.LoggerNameOffset = uint32(unsafe.Offsetof(b.Name))
	b.Properties.LogFileNameOffset = uint32(unsafe.Offsetof(b.Path))
	return b
}
func usbTraceQuery(j usbTraceJournal) (*wpdTracePropertyBuffer, bool, error) {
	b := usbTraceQueryProperties(j)
	r, _, _ := wpdControlTrace.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(j.Name))), uintptr(unsafe.Pointer(b)), 0)
	q := usbTraceQueryEvidence{Observed: true, NativeCode: uint32(r)}
	if r != 0 {
		if r == 4201 {
			return b, false, nil
		}
		return b, false, errors.New("USB_TRACE_QUERY_FAILED")
	}
	g, _ := windows.GUIDFromString(j.GUID)
	q.GUIDMatches = b.Properties.Wnode.GUID == g
	q.Mode = b.Properties.LogFileMode
	q.MaxFile = b.Properties.MaximumFileSize
	q.NameOffset = b.Properties.LoggerNameOffset
	q.FileOffset = b.Properties.LogFileNameOffset
	q.BufferBytes = b.Properties.Wnode.Size
	raw := unsafe.Slice((*byte)(unsafe.Pointer(b)), int(unsafe.Sizeof(*b)))
	q = usbTraceCompareQuery(raw, q, j.Name)
	if q.Mismatch != 0 {
		return b, false, errors.New("USB_TRACE_SESSION_NOT_OWNED")
	}
	return b, true, nil
}

func usbTraceRestoreLocked(dir string) error {
	j, e := usbTraceReadJournal(dir)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if j.Stopped {
		return nil
	}
	b, found, e := usbTraceQuery(j)
	if e != nil {
		return e
	}
	if found {
		r, _, _ := wpdControlTrace.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(j.Name))), uintptr(unsafe.Pointer(b)), 1)
		if r != 0 && r != 4201 {
			return errors.New("USB_TRACE_STOP_FAILED")
		}
		_, found, e = usbTraceQuery(j)
		if e != nil || found {
			return errors.New("USB_TRACE_STOP_UNCONFIRMED")
		}
	}
	j.Stopped = true
	return usbTraceWriteJournal(dir, j)
}
func RestoreLocalUSBTrace(dir string) error {
	h, e := usbTraceLease(dir)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	return usbTraceRestoreLocked(dir)
}
