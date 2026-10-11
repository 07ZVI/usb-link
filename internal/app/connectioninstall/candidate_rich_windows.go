//go:build windows && amd64

package connectioninstall

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
	"time"
	"unsafe"
)

// The rich leaf is separate so previous workers continue decoding their unchanged
// 4096-byte schema1 status. Neither reader nor writer participates in readiness.
func candidateRichPath(root, id string) (string, error) {
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		return "", fmt.Errorf("candidate rich identity malformed")
	}
	return filepath.Join(root, "candidate-diagnostics-"+id+".json"), nil
}
func (m *RemoteManager) SetRichStartupFailureDetails(f func() *remoteupdate.CandidateRichObservation) {
	m.mu.Lock()
	m.richStartupFailureDetails = f
	m.mu.Unlock()
	m.guardCandidateStatusSnapshot()
}

// Historical display uses the recorded signed job, not the current live service
// identity or Mac wall clock. Signature/expiry are checked at the Windows writer
// observation time only for diagnostic provenance, never launch authorization.
func (m *RemoteManager) CandidateStartupRichDiagnostics() *remoteupdate.CandidateRichReceipt {
	e := verifyCandidateRichRoot(m.root)
	if e != nil {
		return nil
	}
	var j UpdateJob
	if readRemote(filepath.Join(m.root, "job.json"), &j) != nil || !j.Guarded {
		return nil
	}
	receipt, e := readCandidateRich(m.root, j.ID)
	if e != nil || !remoteupdate.CandidateRichMatches(receipt, candidateIdentity(j)) || j.Manifest.Verify(remoteupdate.PublisherKey(), "0.0.0", time.Unix(0, receipt.ObservedUnixNano)) != nil {
		return nil
	}
	var final UpdateJob
	if readRemote(filepath.Join(m.root, "job.json"), &final) != nil || !final.Guarded || candidateIdentity(final) != candidateIdentity(j) || final.Manifest != j.Manifest {
		return nil
	}
	e = verifyCandidateRichRoot(m.root)
	if e != nil {
		return nil
	}
	return &receipt
}

// No directory creation or repair on the historical read-only status path.
func verifyCandidateRichRoot(root string) error {
	if noReparse(root) != nil {
		return fmt.Errorf("candidate diagnostics root unproven")
	}
	actual, e := windows.GetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	expected, ee := windows.SecurityDescriptorFromString(remoteACL)
	if e != nil || ee != nil || !sameACL(actual, expected) {
		return fmt.Errorf("candidate diagnostics root protection unproven")
	}
	return nil
}

func readCandidateRich(root, id string) (remoteupdate.CandidateRichReceipt, error) {
	var v remoteupdate.CandidateRichReceipt
	path, e := candidateRichPath(root, id)
	if e != nil {
		return v, e
	}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return v, e
	}
	var info windows.ByHandleFileInformation
	sd, se := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	expected, ee := windows.SecurityDescriptorFromString(remoteACL)
	if se != nil || ee != nil || !candidateStatusOwner(sd) || !sameACL(sd, expected) || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.FileSizeHigh != 0 || info.FileSizeLow > remoteupdate.CandidateRichByteLimit {
		windows.CloseHandle(h)
		return v, fmt.Errorf("candidate status protection unproven")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return v, fmt.Errorf("candidate status unreadable")
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, remoteupdate.CandidateRichByteLimit+1))
	if e != nil {
		return v, e
	}
	return remoteupdate.DecodeCandidateRich(data)
}
func writeCandidateRich(root string, v remoteupdate.CandidateRichReceipt) error {
	fresh, e := remoteRoot()
	if e != nil || fresh != root {
		return fmt.Errorf("candidate status root changed")
	}
	path, e := candidateRichPath(root, v.JobID)
	if e != nil {
		return e
	}
	old, e := readCandidateRich(root, v.JobID)
	initialAbsent := errors.Is(e, windows.ERROR_FILE_NOT_FOUND)
	if e == nil && (old.CandidateIdentity != v.CandidateIdentity || old.Schema != 1 || old.ObservedUnixNano > v.ObservedUnixNano) {
		return fmt.Errorf("candidate status previous identity changed")
	}
	if e != nil && !errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
		return e
	}
	if e == nil {
		v, e = remoteupdate.MergeCandidateRich(old, v)
	} else {
		v, e = remoteupdate.MergeCandidateRich(remoteupdate.CandidateRichReceipt{}, v)
	}
	if e != nil {
		return e
	}
	b, e := json.Marshal(v)
	if e != nil || len(b) > remoteupdate.CandidateRichByteLimit {
		return fmt.Errorf("candidate status too large")
	}
	sd, e := windows.SecurityDescriptorFromString(remoteACL)
	if e != nil {
		return e
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	tmp := filepath.Join(root, "candidate-diagnostics-"+hex.EncodeToString(nonce[:])+".tmp")
	defer os.Remove(tmp)
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(tmp), windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return e
	}
	var info windows.ByHandleFileInformation
	actual, protectionErr := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if protectionErr != nil || !candidateStatusOwner(actual) || !sameACL(actual, sd) || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return fmt.Errorf("candidate status temp protection unproven")
	}
	f := os.NewFile(uintptr(h), tmp)
	if f == nil {
		windows.CloseHandle(h)
		return fmt.Errorf("candidate status temp unreadable")
	}
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
	fresh, e = remoteRoot()
	if e != nil || fresh != root {
		return fmt.Errorf("candidate status root changed")
	}
	current, re := readCandidateRich(root, v.JobID)
	if initialAbsent {
		if !errors.Is(re, windows.ERROR_FILE_NOT_FOUND) {
			return fmt.Errorf("candidate status appeared during write")
		}
	} else if re != nil || !reflect.DeepEqual(current, old) {
		return fmt.Errorf("candidate status changed during write")
	}
	// Do not publish after this candidate's actual launch ownership changed.
	j, e := validatedJob(v.JobID, "")
	if e != nil || !j.Guarded || j.Status != "starting" || candidateIdentity(j) != v.CandidateIdentity || verifyCoreCandidateJob(j) != nil {
		return fmt.Errorf("candidate diagnostics launch changed")
	}
	self, se := os.Executable()
	creation, ce := processCreation(uint32(os.Getpid()))
	if se != nil || ce != nil || j.CandidatePID != uint32(os.Getpid()) || j.CandidateCreation != creation || !strings.EqualFold(j.CandidateExecutable, self) {
		return fmt.Errorf("candidate diagnostics self changed")
	}
	if e = windows.MoveFileEx(windows.StringToUTF16Ptr(tmp), windows.StringToUTF16Ptr(path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return e
	}
	readback, e := readCandidateRich(root, v.JobID)
	if e != nil || !reflect.DeepEqual(readback, v) {
		return fmt.Errorf("candidate status durable readback unproven")
	}
	return nil
}
