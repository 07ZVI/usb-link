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
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
	"time"
	"unsafe"
)

func candidateStatusPath(root, id string) (string, error) {
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		return "", fmt.Errorf("candidate status identity malformed")
	}
	return filepath.Join(root, "candidate-status-"+id+".json"), nil
}

func candidateIdentity(j UpdateJob) remoteupdate.CandidateIdentity {
	return remoteupdate.CandidateIdentity{JobID: j.ID, Version: j.Manifest.Version, SHA256: j.Manifest.SHA256, PID: j.CandidatePID, Creation: j.CandidateCreation}
}
func (m *RemoteManager) SetStartupFailureDetails(f func() remoteupdate.CandidateStartupObservation) {
	m.mu.Lock()
	m.startupFailureDetails = f
	m.mu.Unlock()
	m.guardCandidateStatusSnapshot()
}

// This is a separate observation receipt. It cannot set startupNormal or
// startupRecorded and the readiness tracker never reads it.
func (m *RemoteManager) guardCandidateStatusSnapshot() {
	m.candidateStatusMu.Lock()
	defer m.candidateStatusMu.Unlock()
	select {
	case <-m.done:
		return
	default:
	}
	m.mu.Lock()
	f := m.startupFailureDetails
	rich := m.richStartupFailureDetails
	closing := m.closing.Load()
	m.mu.Unlock()
	if closing || f == nil || startupAckJobID() == "" {
		return
	}
	id := startupAckJobID()
	var initial UpdateJob
	if readRemote(filepath.Join(m.root, "job.json"), &initial) != nil || initial.ID != id || initial.Status != "starting" || !initial.Guarded || initial.Manifest.Version != m.version {
		return
	}
	if ValidateRemoteLaunch(id, m.version) != nil {
		return
	}
	j, e := validatedJob(id, "")
	if e != nil || !j.Guarded || j.Status != "starting" || verifyCoreCandidateJob(j) != nil {
		return
	}
	self, se := os.Executable()
	created, ce := processCreation(uint32(os.Getpid()))
	if se != nil || ce != nil || j.CandidatePID != uint32(os.Getpid()) || j.CandidateCreation != created || !strings.EqualFold(j.CandidateExecutable, self) {
		return
	}
	observation := remoteupdate.SanitizeCandidateStartup(f())
	var detailed *remoteupdate.CandidateRichObservation
	if rich != nil {
		detailed = remoteupdate.CopyCandidateRichObservation(rich())
	}
	fresh, e := validatedJob(id, "")
	if e != nil || fresh.Status != "starting" || candidateIdentity(fresh) != candidateIdentity(j) || fresh.CandidateExecutable != j.CandidateExecutable || verifyCoreCandidateJob(fresh) != nil {
		return
	}
	if m.closing.Load() {
		return
	}
	select {
	case <-m.done:
		return
	default:
	}
	_ = writeCandidateStatus(m.root, remoteupdate.CandidateStatusReceipt{Schema: 1, CandidateIdentity: candidateIdentity(j), ObservedUnixNano: time.Now().UnixNano(), Observation: observation})
	if detailed != nil {
		_ = writeCandidateRich(m.root, remoteupdate.CandidateRichReceipt{Schema: 1, CandidateIdentity: candidateIdentity(j), ObservedUnixNano: time.Now().UnixNano(), Observation: *detailed})
	}
}

// Read only the fixed protected receipt through a held read handle. Unknown
// ACLs, reparse points, hardlinks, excess bytes or unknown JSON are not repaired.
func readCandidateStatus(root, id string) (remoteupdate.CandidateStatusReceipt, error) {
	var v remoteupdate.CandidateStatusReceipt
	path, e := candidateStatusPath(root, id)
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
	if se != nil || ee != nil || !candidateStatusOwner(sd) || !sameACL(sd, expected) || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.FileSizeHigh != 0 || info.FileSizeLow > 4096 {
		windows.CloseHandle(h)
		return v, fmt.Errorf("candidate status protection unproven")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return v, fmt.Errorf("candidate status unreadable")
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil {
		return v, e
	}
	return remoteupdate.DecodeCandidateStatus(data)
}
func captureCandidateFailure(root string, j UpdateJob, reason string) remoteupdate.CandidateFailure {
	receipt, e := readCandidateStatus(root, j.ID)
	if e != nil {
		receipt = remoteupdate.CandidateStatusReceipt{}
	}
	return remoteupdate.RecordCandidateFailure(candidateIdentity(j), reason, receipt, time.Now())
}
func candidateFailureStatus(j UpdateJob) map[string]string {
	out := remoteupdate.CandidateFailureDisplay(j.CandidateFailure, candidateIdentity(j))
	if j.CandidateFailure.NativeError != 0 && out["candidate_failure_code"] == "USB_HOST_NATIVE_OPERATION_FAILED" {
		out["candidate_failure_native_error"] = fmt.Sprint(j.CandidateFailure.NativeError)
	}
	if j.CandidateFailure.NativeHRESULT != 0 && out["candidate_failure_operation"] != "" {
		out["candidate_failure_hresult"] = fmt.Sprintf("%08X", j.CandidateFailure.NativeHRESULT)
	}
	return out
}

func candidateStatusOwner(sd *windows.SECURITY_DESCRIPTOR) bool {
	if sd == nil {
		return false
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !owner.IsValid() {
		return false
	}
	if owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	return e == nil && windows.EqualSid(owner, user.User.Sid)
}
func writeCandidateStatus(root string, v remoteupdate.CandidateStatusReceipt) error {
	fresh, e := remoteRoot()
	if e != nil || fresh != root {
		return fmt.Errorf("candidate status root changed")
	}
	path, e := candidateStatusPath(root, v.JobID)
	if e != nil {
		return e
	}
	old, e := readCandidateStatus(root, v.JobID)
	initialAbsent := errors.Is(e, windows.ERROR_FILE_NOT_FOUND)
	if e == nil && (old.CandidateIdentity != v.CandidateIdentity || old.Schema != 1 || old.ObservedUnixNano > v.ObservedUnixNano) {
		return fmt.Errorf("candidate status previous identity changed")
	}
	if e != nil && !errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
		return e
	}
	b, e := json.Marshal(v)
	if e != nil || len(b) > 4096 {
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
	tmp := filepath.Join(root, "candidate-status-"+hex.EncodeToString(nonce[:])+".tmp")
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
	current, re := readCandidateStatus(root, v.JobID)
	if initialAbsent {
		if !errors.Is(re, windows.ERROR_FILE_NOT_FOUND) {
			return fmt.Errorf("candidate status appeared during write")
		}
	} else if re != nil || current != old {
		return fmt.Errorf("candidate status changed during write")
	}
	if e = windows.MoveFileEx(windows.StringToUTF16Ptr(tmp), windows.StringToUTF16Ptr(path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return e
	}
	readback, e := readCandidateStatus(root, v.JobID)
	if e != nil || readback != v {
		return fmt.Errorf("candidate status durable readback unproven")
	}
	return nil
}

// CaptureStartupFailureDetails performs the same fixed diagnostic observation
// immediately before a known local child failure cancels the parent. It cannot
// acknowledge readiness or choose a process/path; all existing checks remain.
func (m *RemoteManager) CaptureStartupFailureDetails() { m.guardCandidateStatusSnapshot() }
