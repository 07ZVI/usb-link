//go:build windows && amd64

package connectioninstall

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"
)

const coreBindingFile = "core-service.json"
const coreLifecycleMutexName = `Global\USBLinkCoreLifecycle-v1`

func coreLifecycleLock() (func() error, error) {
	return acquireUpgradeJobMutex(coreLifecycleMutexName, 5000)
}

var coreOwnerSID atomic.Pointer[string]

// VerifyCoreExecutable is stricter than legacy startup verification: only the
// protected active program or an authenticated transaction source; never a
// download/user path. Temporary sources require a nonterminal exact receipt.
func VerifyCoreExecutable(exe string) error {
	root, e := trustedCoreDirectory(filepath.Dir(exe))
	if e != nil || filepath.Base(exe) != BinaryName || Verify(exe) != nil {
		return fmt.Errorf("CORE_INSTALLED_SOURCE_UNPROVEN")
	}
	legacy, e := legacyRoot()
	if e != nil || strings.EqualFold(root, legacy) {
		return fmt.Errorf("CORE_INSTALLED_SOURCE_UNPROVEN")
	}
	for _, p := range []string{root, filepath.Join(root, "product-id.txt"), filepath.Dir(exe), filepath.Join(filepath.Dir(exe), "ownership.json"), exe} {
		if _, e = coreProtectedRead(p, p == root || p == filepath.Dir(exe), false); e != nil {
			return e
		}
	}
	return nil
}

// Read handles reject redirection/hard links and writable non-admin ownership.
// Inherited read/execute grants to Users remain valid for installed UI binaries.
func coreProtectedRead(path string, directory, read bool) ([]byte, error) {
	return coreProtectedReadBounded(path, directory, read, 4096)
}
func coreProtectedReadBounded(path string, directory, read bool, limit int) ([]byte, error) {
	if limit <= 0 || limit > 32768 {
		return nil, fmt.Errorf("CORE_FILE_BOUND_INVALID")
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, flags, 0)
	if e != nil {
		return nil, e
	}
	var info windows.ByHandleFileInformation
	sd, se := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if se != nil || windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || !directory && info.NumberOfLinks != 1 || directory != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) || !coreFileACLValid(sd) {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("CORE_FILE_PROTECTION_UNPROVEN")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("CORE_FILE_UNREADABLE")
	}
	defer f.Close()
	if !read {
		return nil, nil
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if e != nil || len(b) > limit {
		return nil, fmt.Errorf("CORE_FILE_UNREADABLE")
	}
	return b, nil
}
func coreFileACLValid(sd *windows.SECURITY_DESCRIPTOR) bool {
	if sd == nil {
		return false
	}
	owner, _, e := sd.Owner()
	ba, be := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	sy, se := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	bu, ue := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if e != nil || be != nil || se != nil || ue != nil || owner == nil || !owner.Equals(ba) && !owner.Equals(sy) {
		return false
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount == 0 || acl.AceCount > 16 {
		return false
	}
	seenBA, seenSY := false, false
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &a) != nil || a == nil || a.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || a.Header.AceFlags & ^byte(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE|windows.INHERITED_ACE) != 0 || a.Header.AceSize < 20 || a.Header.AceSize > 68 {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
		count := *(*byte)(unsafe.Add(unsafe.Pointer(sid), 1))
		if uint32(a.Header.AceSize) != 16+4*uint32(count) || !sid.IsValid() {
			return false
		}
		if sid.Equals(ba) {
			seenBA = true
		} else if sid.Equals(sy) {
			seenSY = true
		} else if !sid.Equals(bu) || uint32(a.Mask) & ^uint32(0x1200a9) != 0 {
			return false
		}
	}
	return seenBA && seenSY
}
func readCoreBinding() (CoreServiceBinding, bool, error) {
	root, e := coreStateDirectory()
	if e != nil {
		return CoreServiceBinding{}, false, e
	}
	path := filepath.Join(root, coreBindingFile)
	b, e := coreProtectedRead(path, false, true)
	if os.IsNotExist(e) || e == windows.ERROR_FILE_NOT_FOUND {
		return CoreServiceBinding{}, false, nil
	}
	if e != nil {
		return CoreServiceBinding{}, false, e
	}
	v, e := parseCoreBinding(b)
	if e != nil {
		return v, true, e
	}
	sid, e := windows.StringToSid(v.OwnerSID)
	if e != nil || !sid.IsValid() {
		return v, true, fmt.Errorf("CORE_OWNER_INVALID")
	}
	if VerifyCoreExecutable(v.Executable) != nil {
		return v, true, fmt.Errorf("CORE_BINDING_SOURCE_CHANGED")
	}
	hash, e := fileHash(v.Executable)
	if e != nil || hash != v.SHA256 {
		return v, true, fmt.Errorf("CORE_BINDING_HASH_CHANGED")
	}
	return v, true, nil
}
func writeCoreBinding(v CoreServiceBinding, old *CoreServiceBinding) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if _, e = parseCoreBinding(b); e != nil {
		return e
	}
	root, e := coreStateDirectory()
	if e != nil {
		return e
	}
	got, found, e := readCoreBinding()
	if e != nil || old == nil && found || old != nil && (!found || got != *old) {
		return fmt.Errorf("CORE_BINDING_CHANGED")
	}
	path := filepath.Join(root, coreBindingFile)
	sd, e := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	temp := path + ".tmp"
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(temp), windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return fmt.Errorf("CORE_BINDING_WRITE_PENDING")
	}
	defer os.Remove(temp)
	f := os.NewFile(uintptr(h), temp)
	if f == nil {
		windows.CloseHandle(h)
		return fmt.Errorf("CORE_BINDING_WRITE_FAILED")
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return fmt.Errorf("CORE_BINDING_WRITE_FAILED")
	}
	if _, e = coreProtectedRead(temp, false, false); e != nil {
		return e
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if old != nil {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if e = windows.MoveFileEx(windows.StringToUTF16Ptr(temp), windows.StringToUTF16Ptr(path), flags); e != nil {
		return e
	}
	got, found, e = readCoreBinding()
	if e != nil || !found || got != v {
		return fmt.Errorf("CORE_BINDING_READBACK_FAILED")
	}
	return nil
}
func ownedCoreService(m *mgr.Mgr) (*mgr.Service, CoreServiceBinding, error) {
	s, e := m.OpenService(CoreServiceName)
	if e != nil {
		return nil, CoreServiceBinding{}, e
	}
	fail := func(e error) (*mgr.Service, CoreServiceBinding, error) {
		s.Close()
		return nil, CoreServiceBinding{}, e
	}
	if e = coreServiceSecurity(s); e != nil {
		return fail(e)
	}
	b, present, e := readCoreBinding()
	if e != nil || !present {
		return fail(fmt.Errorf("CORE_SERVICE_BINDING_UNPROVEN"))
	}
	c, e := s.Config()
	if e != nil {
		return fail(e)
	}
	args, e := windows.DecomposeCommandLine(c.BinaryPathName)
	if e != nil || validateCoreServiceConfig(b.Executable, c.ServiceStartName, c.ServiceType, c.StartType, c.DelayedAutoStart, args) != nil {
		return fail(fmt.Errorf("CORE_SERVICE_CONFIG_CHANGED"))
	}
	if e = coreServiceExecutionPolicy(s, c); e != nil {
		return fail(e)
	}
	return s, b, nil
}
func CurrentCoreBinding() (CoreServiceBinding, error) {
	m, e := mgr.Connect()
	if e != nil {
		return CoreServiceBinding{}, e
	}
	defer m.Disconnect()
	s, b, e := ownedCoreService(m)
	if e != nil {
		return b, e
	}
	s.Close()
	return b, nil
}
func ActivateCoreOwner(exe string) (CoreServiceBinding, error) {
	b, e := CurrentCoreBinding()
	if e != nil || b.Executable != exe || VerifyCoreExecutable(exe) != nil {
		return b, fmt.Errorf("CORE_SERVICE_SOURCE_CHANGED")
	}
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	session, e2 := shareTokenDWORD(windows.GetCurrentProcessToken(), windows.TokenSessionId)
	if e != nil || e2 != nil || u.User.Sid.String() != "S-1-5-18" || session != 0 {
		return b, fmt.Errorf("CORE_SYSTEM_SESSION0_REQUIRED")
	}
	sid := b.OwnerSID
	if activated := coreOwnerSID.Load(); activated != nil && *activated != sid {
		return b, fmt.Errorf("CORE_BOUND_OWNER_CHANGED")
	}
	coreOwnerSID.Store(&sid)
	return b, nil
}
func BoundCoreOwnerSID() (string, bool) {
	p := coreOwnerSID.Load()
	if p == nil {
		return "", false
	}
	return *p, true
}

func coreServiceSecurity(s *mgr.Service) error {
	sd, e := windows.GetSecurityInfo(s.Handle, windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || sd == nil {
		return fmt.Errorf("CORE_SCM_SECURITY_UNPROVEN")
	}
	ba, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	sy, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !owner.Equals(ba) && !owner.Equals(sy) {
		return fmt.Errorf("CORE_SCM_OWNER_UNPROVEN")
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount > 32 {
		return fmt.Errorf("CORE_SCM_ACL_UNPROVEN")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &a) != nil || a == nil || a.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || a.Header.AceFlags & ^byte(windows.INHERITED_ACE) != 0 || a.Header.AceSize < 20 || a.Header.AceSize > 68 {
			return fmt.Errorf("CORE_SCM_ACL_UNPROVEN")
		}
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
		count := *(*byte)(unsafe.Add(unsafe.Pointer(sid), 1))
		if uint32(a.Header.AceSize) != 16+4*uint32(count) || !sid.IsValid() {
			return fmt.Errorf("CORE_SCM_ACL_UNPROVEN")
		}
		if !sid.Equals(ba) && !sid.Equals(sy) && uint32(a.Mask)&uint32(0xf0000000|windows.SERVICE_CHANGE_CONFIG|windows.SERVICE_START|windows.SERVICE_STOP|windows.DELETE|windows.WRITE_DAC|windows.WRITE_OWNER) != 0 {
			return fmt.Errorf("CORE_SCM_FOREIGN_WRITE")
		}
	}
	return nil
}

// Unknown dependencies, restricted SID modes and recovery commands can change
// what runs as SYSTEM. They are not repaired or treated as our owned service.
func coreServiceExecutionPolicy(s *mgr.Service, c mgr.Config) error {
	if c.SidType != windows.SERVICE_SID_TYPE_NONE || c.ErrorControl != 0 || c.TagId != 0 || c.LoadOrderGroup != "" || len(c.Dependencies) != 0 {
		return fmt.Errorf("CORE_SERVICE_EXECUTION_CONFIG_CHANGED")
	}
	actions, e := s.RecoveryActions()
	if e != nil || len(actions) != 0 {
		return fmt.Errorf("CORE_SERVICE_RECOVERY_CHANGED")
	}
	command, e := s.RecoveryCommand()
	if e != nil || command != "" {
		return fmt.Errorf("CORE_SERVICE_RECOVERY_CHANGED")
	}
	message, e := s.RebootMessage()
	if e != nil || message != "" {
		return fmt.Errorf("CORE_SERVICE_RECOVERY_CHANGED")
	}
	flag, e := s.RecoveryActionsOnNonCrashFailures()
	if e != nil || flag {
		return fmt.Errorf("CORE_SERVICE_RECOVERY_CHANGED")
	}
	return nil
}
func stopCore(s *mgr.Service) error {
	if coreServiceSecurity(s) != nil {
		return fmt.Errorf("CORE_SCM_SECURITY_UNPROVEN")
	}
	state, e := s.Query()
	if e != nil {
		return e
	}
	if state.State == svc.Stopped {
		return nil
	}
	if state.State != svc.StopPending {
		if _, e = s.Control(svc.Stop); e != nil {
			return e
		}
	}
	end := time.Now().Add(90 * time.Second)
	for time.Now().Before(end) {
		state, e = s.Query()
		if e != nil {
			return e
		}
		if state.State == svc.Stopped {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("CORE_SERVICE_CLEANUP_PENDING")
}
func StartCoreService() (result error) {
	unlock, e := coreLifecycleLock()
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, unlock()) }()
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, _, e := ownedCoreService(m)
	if e != nil {
		return e
	}
	defer s.Close()
	state, e := s.Query()
	if e != nil {
		return e
	}
	if state.State == svc.Running {
		return nil
	}
	if state.State != svc.Stopped {
		return fmt.Errorf("CORE_SERVICE_TRANSITION_PENDING")
	}
	if e = s.Start(); e != nil {
		return e
	}
	end := time.Now().Add(30 * time.Second)
	for time.Now().Before(end) {
		state, e = s.Query()
		if e != nil {
			return e
		}
		if state.State == svc.Running {
			return nil
		}
		if state.State == svc.Stopped {
			return fmt.Errorf("CORE_SERVICE_START_FAILED")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("CORE_SERVICE_START_PENDING")
}
func StopCoreService() (result error) {
	unlock, e := coreLifecycleLock()
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, unlock()) }()
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, _, e := ownedCoreService(m)
	if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return nil
	}
	if e != nil {
		return e
	}
	defer s.Close()
	return stopCore(s)
}

// StopExpectedCoreService retires only the exact binding held by a failed
// bootstrap. A completed/later migration cannot be stopped by an obsolete UI.
// The same lifecycle lock covers identity readback and SCM stop, so an installer
// cannot replace the binding between the comparison and the control request.
func StopExpectedCoreService(expected CoreServiceBinding) (result error) {
	b, e := json.Marshal(expected)
	if e != nil {
		return e
	}
	if _, e := parseCoreBinding(b); e != nil {
		return fmt.Errorf("CORE_SERVICE_EXPECTED_BINDING_INVALID")
	}
	unlock, e := coreLifecycleLock()
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, unlock()) }()
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, current, e := ownedCoreService(m)
	if e != nil {
		return e
	}
	defer s.Close()
	if current != expected {
		return fmt.Errorf("CORE_SERVICE_EXPECTED_BINDING_CHANGED")
	}
	return stopCore(s)
}
func VerifyCoreServiceProcess(pid uint32) error {
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, b, e := ownedCoreService(m)
	if e != nil {
		return e
	}
	defer s.Close()
	status, e := s.Query()
	if e != nil || status.State != svc.Running || status.ProcessId != pid {
		return fmt.Errorf("CORE_SERVICE_PID_CHANGED")
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	var path [32768]uint16
	n := uint32(len(path))
	if windows.QueryFullProcessImageName(h, 0, &path[0], &n) != nil || !strings.EqualFold(windows.UTF16ToString(path[:n]), b.Executable) || VerifyCoreExecutable(b.Executable) != nil {
		return fmt.Errorf("CORE_SERVICE_PROCESS_SOURCE_CHANGED")
	}
	var t windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &t) != nil {
		return fmt.Errorf("CORE_SERVICE_PROCESS_TOKEN_FAILED")
	}
	defer t.Close()
	u, e := t.GetTokenUser()
	session, se := shareTokenDWORD(t, windows.TokenSessionId)
	if e != nil || se != nil || u.User.Sid.String() != "S-1-5-18" || session != 0 {
		return fmt.Errorf("CORE_SERVICE_PROCESS_IDENTITY_CHANGED")
	}
	fresh, e := s.Query()
	if e != nil || fresh.State != svc.Running || fresh.ProcessId != pid {
		return fmt.Errorf("CORE_SERVICE_PID_CHANGED")
	}
	return nil
}

// SetCoreServiceExecutable is the only SCM migration entry. The durable
// transition is written before any stop/config change; unfinished transitions
// restore only the exact prior owned binding and never start a guessed owner.
func InstallCoreService(exe string) (result error) {
	return installCoreService(exe, nil)
}

// Creation is observed only inside the SCM mutation lock, never inferred from
// an earlier absence read. The result survives later readback/start failures.
func InstallCoreServiceObserved(exe string) (created bool, err error) {
	err = installCoreService(exe, &created)
	return created, err
}

func installCoreService(exe string, created *bool) error {
	return installCoreServicePrepared(exe, created, "")
}
func installCoreServicePrepared(exe string, created *bool, preparedVersion string) error {
	return bindCoreService(exe, created, preparedVersion, true)
}
func bindCoreService(exe string, created *bool, preparedVersion string, start bool) (result error) {
	unlock, e := coreLifecycleLock()
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, unlock()) }()
	if preparedVersion != "" {
		if e := ValidatePreparedInstall(preparedVersion); e != nil {
			return e
		}
	}
	if !windows.GetCurrentProcessToken().IsElevated() || VerifyCoreExecutable(exe) != nil {
		return fmt.Errorf("CORE_INSTALL_SOURCE_REJECTED")
	}
	if e := recoverCoreServiceTransition(); e != nil {
		return e
	}
	old, found, e := readCoreBinding()
	if e != nil {
		return e
	}
	var owner string
	if found {
		owner = old.OwnerSID
	} else {
		u, e := windows.GetCurrentProcessToken().GetTokenUser()
		session, se := shareTokenDWORD(windows.GetCurrentProcessToken(), windows.TokenSessionId)
		if e != nil || se != nil || session == 0 {
			return fmt.Errorf("CORE_INSTALL_USER_REQUIRED")
		}
		owner = u.User.Sid.String()
	}
	hash, e := fileHash(exe)
	if e != nil {
		return e
	}
	next := CoreServiceBinding{1, ProductID, owner, exe, hash}
	b, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if _, e = parseCoreBinding(b); e != nil {
		return e
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	var s *mgr.Service
	if found {
		s, _, e = ownedCoreService(m)
		if e != nil {
			return e
		}
		defer s.Close()
	} else {
		s, e = m.OpenService(CoreServiceName)
		if e == nil {
			s.Close()
			return fmt.Errorf("CORE_FOREIGN_SERVICE_PRESERVED")
		}
		if e != windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return e
		}
	}
	if found && old == next {
		if start {
			return StartCoreService()
		}
		return stopCore(s)
	}
	transition := coreServiceTransition{Version: 1, Next: next}
	if found {
		copy := old
		transition.Previous = &copy
	}
	if e = writeCoreTransition(transition); e != nil {
		return e
	}
	if found {
		if e = stopCore(s); e != nil {
			return e
		}
	}
	if e = writeCoreBinding(next, transition.Previous); e != nil {
		return e
	}
	command := windows.ComposeCommandLine([]string{exe, CoreServiceArgument})
	if found {
		c, ce := s.Config()
		if ce != nil {
			return ce
		}
		args, ae := windows.DecomposeCommandLine(c.BinaryPathName)
		if ae != nil || validateCoreServiceConfig(old.Executable, c.ServiceStartName, c.ServiceType, c.StartType, c.DelayedAutoStart, args) != nil {
			return fmt.Errorf("CORE_SERVICE_CONFIG_CHANGED")
		}
		c.BinaryPathName = command
		if !start {
			c.StartType = mgr.StartManual
		}
		if e = s.UpdateConfig(c); e != nil {
			return e
		}
	} else {
		s, e = m.CreateService(CoreServiceName, exe, mgr.Config{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, StartType: mgr.StartAutomatic, ServiceStartName: "LocalSystem", DisplayName: "USB Link", Description: "USB Link core: owned USB networking, local UI IPC; no interactive Session0 UI."}, CoreServiceArgument)
		if e != nil {
			return e
		}
		if created != nil {
			*created = true
		}
		defer s.Close()
	}
	verified, got, e := ownedCoreService(m)
	if e != nil {
		return e
	}
	verified.Close()
	if got != next {
		return fmt.Errorf("CORE_SERVICE_INSTALL_READBACK_FAILED")
	}
	if e = clearCoreTransition(transition); e != nil {
		return e
	}
	if start {
		return StartCoreService()
	}
	return nil
}
func RemoveCoreService() (result error) {
	return removeCoreService(nil)
}

// Only a bootstrap which observed actual first creation may choose this API.
// It cannot remove or recover a replacement binding or an unknown transition.
func RemoveExpectedCoreService(expected CoreServiceBinding) error {
	b, e := json.Marshal(expected)
	if e != nil {
		return e
	}
	if _, e = parseCoreBinding(b); e != nil {
		return fmt.Errorf("CORE_SERVICE_EXPECTED_BINDING_INVALID")
	}
	return removeCoreService(&expected)
}

func removeCoreService(expected *CoreServiceBinding) (result error) {
	unlock, e := coreLifecycleLock()
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, unlock()) }()
	return removeCoreServiceUnlocked(expected)
}

// Caller retains coreLifecycleLock; only a validated local uninstall may use
// this to finish exact removal without opening a Start/replace race.
func removeCoreServiceUnlocked(expected *CoreServiceBinding) error {
	if expected == nil {
		if e := recoverCoreServiceTransition(); e != nil {
			return e
		}
	} else {
		transition, pending, e := readCoreTransition()
		if e != nil || pending && (transition.Previous != nil || transition.Next != *expected) {
			return fmt.Errorf("CORE_SERVICE_EXPECTED_TRANSITION_PENDING")
		}
		if pending {
			// A first-creation transition can be recovered only for this exact
			// expected candidate. Existing recovery repeats source/config/ACL
			// proofs and confirms SCM absence before touching the binding.
			return recoverCoreServiceTransition()
		}
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, b, e := ownedCoreService(m)
	if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		binding, present, e := readCoreBinding()
		if e != nil {
			return e
		}
		if !present {
			return nil
		}
		if expected != nil && binding != *expected {
			return fmt.Errorf("CORE_SERVICE_EXPECTED_BINDING_CHANGED")
		}
		return clearAbsentCoreBinding(m, binding)
	}
	if e != nil {
		return e
	}
	defer func() {
		if s != nil {
			s.Close()
		}
	}()
	if expected != nil && b != *expected {
		return fmt.Errorf("CORE_SERVICE_EXPECTED_BINDING_CHANGED")
	}
	if e = stopCore(s); e != nil {
		return e
	}
	fresh, got, e := ownedCoreService(m)
	if e != nil {
		return e
	}
	defer func() {
		if fresh != nil {
			fresh.Close()
		}
	}()
	if got != b {
		return fmt.Errorf("CORE_SERVICE_BINDING_CHANGED")
	}
	if e = fresh.Delete(); e != nil {
		return e
	}
	s.Close()
	s = nil
	fresh.Close()
	fresh = nil
	end := time.Now().Add(10 * time.Second)
	for time.Now().Before(end) {
		check, e := m.OpenService(CoreServiceName)
		if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			root, _ := coreStateDirectory()
			got, present, e := readCoreBinding()
			if e != nil || !present || got != b {
				return fmt.Errorf("CORE_SERVICE_BINDING_CHANGED")
			}
			if e = os.Remove(filepath.Join(root, coreBindingFile)); e != nil {
				return e
			}
			_, present, e = readCoreBinding()
			if e != nil || present {
				return fmt.Errorf("CORE_SERVICE_REMOVAL_UNCONFIRMED")
			}
			return nil
		}
		if e == nil {
			check.Close()
		} else if e != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			return e
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("CORE_SERVICE_REMOVAL_PENDING")
}

// Retry after SCM's deferred deletion can remove only the exact authenticated
// binding once the service name is authoritatively absent twice.
func clearAbsentCoreBinding(m *mgr.Mgr, b CoreServiceBinding) error {
	check, e := m.OpenService(CoreServiceName)
	if e == nil {
		check.Close()
		return fmt.Errorf("CORE_SERVICE_REMOVAL_UNCONFIRMED")
	}
	if e != windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return e
	}
	got, present, e := readCoreBinding()
	if e != nil || !present || got != b {
		return fmt.Errorf("CORE_SERVICE_BINDING_CHANGED")
	}
	check, e = m.OpenService(CoreServiceName)
	if e == nil {
		check.Close()
		return fmt.Errorf("CORE_SERVICE_REMOVAL_UNCONFIRMED")
	}
	if e != windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return e
	}
	root, _ := coreStateDirectory()
	if e = os.Remove(filepath.Join(root, coreBindingFile)); e != nil {
		return e
	}
	_, present, e = readCoreBinding()
	if e != nil || present {
		return fmt.Errorf("CORE_SERVICE_REMOVAL_UNCONFIRMED")
	}
	return nil
}

type CoreServiceObservation struct {
	ObservationOnly bool   `json:"observation_only"`
	Installed       bool   `json:"installed"`
	State           uint32 `json:"state"`
	PID             uint32 `json:"pid"`
	OwnerBound      bool   `json:"owner_bound"`
	ProcessVerified bool   `json:"process_verified"`
	Problem         string `json:"problem,omitempty"`
	Automatic       bool   `json:"automatic"`
}

func CoreServiceStatus() CoreServiceObservation {
	out := CoreServiceObservation{ObservationOnly: true}
	m, e := mgr.Connect()
	if e != nil {
		out.Problem = "CORE_SCM_UNAVAILABLE"
		return out
	}
	defer m.Disconnect()
	s, _, e := ownedCoreService(m)
	if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return out
	}
	if e != nil {
		out.Problem = "CORE_SERVICE_OWNERSHIP_UNPROVEN"
		return out
	}
	defer s.Close()
	out.Installed = true
	out.OwnerBound = true
	config, e := s.Config()
	if e != nil {
		out.Problem = "CORE_SERVICE_CONFIG_UNAVAILABLE"
		return out
	}
	out.Automatic = config.StartType == mgr.StartAutomatic
	state, e := s.Query()
	if e != nil {
		out.Problem = "CORE_SERVICE_STATE_UNAVAILABLE"
		return out
	}
	out.State = uint32(state.State)
	out.PID = state.ProcessId
	if state.State == svc.Running {
		out.ProcessVerified = VerifyCoreServiceProcess(state.ProcessId) == nil
		if !out.ProcessVerified {
			out.Problem = "CORE_SERVICE_PROCESS_UNPROVEN"
		}
	}
	return out
}

// Automatic-start preference affects the next boot only. Switching to demand
// start never interrupts the running core or silently changes its identity.
func SetCoreAutomatic(enabled bool) (result error) {
	unlock, e := coreLifecycleLock()
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, unlock()) }()
	if !windows.GetCurrentProcessToken().IsElevated() {
		if _, ok := BoundCoreOwnerSID(); !ok {
			return fmt.Errorf("CORE_STARTUP_ADMIN_REQUIRED")
		}
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, b, e := ownedCoreService(m)
	if e != nil {
		return e
	}
	defer s.Close()
	c, e := s.Config()
	if e != nil {
		return e
	}
	if enabled {
		c.StartType = mgr.StartAutomatic
	} else {
		c.StartType = mgr.StartManual
	}
	c.DelayedAutoStart = false
	fresh, got, e := ownedCoreService(m)
	if e != nil {
		return e
	}
	defer fresh.Close()
	if got != b {
		return fmt.Errorf("CORE_STARTUP_BINDING_CHANGED")
	}
	if e = fresh.UpdateConfig(c); e != nil {
		return e
	}
	observed, e := fresh.Config()
	if e != nil || observed.StartType != c.StartType || observed.DelayedAutoStart || observed.BinaryPathName != c.BinaryPathName {
		return fmt.Errorf("CORE_STARTUP_READBACK_FAILED")
	}
	check, got, e := ownedCoreService(m)
	if e != nil {
		return e
	}
	check.Close()
	if got != b {
		return fmt.Errorf("CORE_STARTUP_BINDING_CHANGED")
	}
	return nil
}
