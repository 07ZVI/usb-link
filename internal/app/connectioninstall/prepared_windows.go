//go:build windows && amd64

package connectioninstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const PreparedInstallArgument = "--prepared-install"

// ValidatePreparedInstall accepts no target, account, command or version from
// the command line. The caller supplies its compiled release version only.
func ValidatePreparedInstall(version string) (result error) {
	phase := "SOURCE"
	fail := func(code string, cause error) error {
		var native syscall.Errno
		_ = errors.As(cause, &native)
		return &preparedInstallFailure{boundedPreparedObservation(version, phase, code, uint32(native))}
	}
	defer func() {
		observation := boundedPreparedObservation(version, "COMPLETE", "OK", 0)
		if result != nil {
			observation = boundedPreparedObservation(version, phase, "PREPARED_INSTALL_VERIFICATION_FAILED", 0)
			var failure *preparedInstallFailure
			if errors.As(result, &failure) {
				observation = failure.observation
			}
		}
		preparedLastObservation.Store(&observation)
	}()
	self, e := os.Executable()
	if e == nil {
		e = VerifyCoreExecutable(self)
	}
	if e != nil {
		return fail("PREPARED_INSTALL_SOURCE_UNPROVEN", e)
	}
	phase = "VERSION"
	receipt, e := readReceipt(filepath.Dir(self))
	if e != nil || receipt.Version != version || !versionPattern.MatchString(version) {
		return fail("PREPARED_INSTALL_VERSION_CHANGED", e)
	}
	phase = "INTERACTIVE_ADMIN"
	token := windows.GetCurrentProcessToken()
	user, e := token.GetTokenUser()
	session, se := shareTokenDWORD(token, windows.TokenSessionId)
	if e != nil || se != nil || !token.IsElevated() || session == 0 || session == 0xffffffff {
		return fail("PREPARED_INSTALL_INTERACTIVE_ADMIN_REQUIRED", errors.Join(e, se))
	}
	phase = "SCM_CONNECT"
	m, e := mgr.Connect()
	if e != nil {
		return fail("PREPARED_INSTALL_SCM_CONNECT_FAILED", e)
	}
	defer m.Disconnect()
	phase = "BINDING"
	binding, found, e := readCoreBinding()
	if e != nil {
		return fail("PREPARED_INSTALL_BINDING_UNPROVEN", e)
	}
	previous := ""
	same := false
	if found {
		phase = "SERVICE_IDENTITY"
		s, b, e := ownedCoreService(m)
		if e != nil {
			return fail("PREPARED_INSTALL_SERVICE_IDENTITY_UNPROVEN", e)
		}
		s.Close()
		if b != binding {
			return fail("PREPARED_INSTALL_BINDING_CHANGED", nil)
		}
		phase = "PREVIOUS_RECEIPT"
		r, e := readReceipt(filepath.Dir(binding.Executable))
		if e != nil {
			return fail("PREPARED_INSTALL_PREVIOUS_RECEIPT_UNPROVEN", e)
		}
		previous = r.Version
		same = strings.EqualFold(self, binding.Executable)
	} else {
		phase = "SERVICE_ABSENCE"
		s, e := m.OpenService(CoreServiceName)
		if e == nil {
			s.Close()
			return fail("PREPARED_INSTALL_UNKNOWN_SERVICE_PRESERVED", nil)
		}
		if e != windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return fail("PREPARED_INSTALL_SERVICE_ABSENCE_UNPROVEN", e)
		}
	}
	phase = "OWNER_VERSION"
	if problem := preparedPolicyProblem(version, previous, user.User.Sid.String(), binding.OwnerSID, found, same); problem != "" {
		return fail(problem, nil)
	}
	phase = "REMOTE_STORE"
	root, e := remoteRoot()
	if e != nil {
		return fail("PREPARED_INSTALL_REMOTE_STORE_UNPROVEN", e)
	}
	path := filepath.Join(root, "job.json")
	phase = "JOB_READ"
	if _, e = os.Lstat(path); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return fail("PREPARED_INSTALL_JOB_READ_FAILED", e)
	}
	if noReparse(path) != nil {
		return fail("PREPARED_INSTALL_JOB_UNPROVEN", e)
	}
	b, e := os.ReadFile(path)
	if e != nil || len(b) > 32768 || !preparedJournalUnique(b) {
		return fail("PREPARED_INSTALL_JOB_UNPROVEN", e)
	}
	phase = "JOB_PARSE"
	var job UpdateJob
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&job) != nil || d.Decode(new(any)) != io.EOF || len(job.ID) != 32 || strings.Trim(job.ID, "0123456789abcdef") != "" {
		return fail("PREPARED_INSTALL_JOB_SCHEMA_UNPROVEN", nil)
	}
	phase = "JOB_IDLE"
	if !preparedJobIdle(job.Status, job.CandidatePID, job.CandidateCreation, job.CandidateExecutable) {
		return fail("PREPARED_INSTALL_UPGRADE_PENDING", nil)
	}
	// Terminal logs may reference released staging bytes. We do not erase logs or
	// require those expired bytes, and never treat an unknown outcome as idle.
	return nil
}

func InstallPreparedCoreServiceObserved(exe, version string) (created bool, err error) {
	err = installCoreServicePrepared(exe, &created, version)
	return
}
