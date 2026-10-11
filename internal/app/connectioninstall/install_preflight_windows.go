//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// Inspect existing ownership before preparing components or copying a new
// release. Deleting Program Files does not unregister SCM or the uninstall key.
// A missing receipt never authorizes taking over an existing service.
func PreflightLocalInstallation() error {
	if e := pendingInstallationRemoval(); e != nil {
		return e
	}
	if err := ownedRegistration(); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(CoreServiceName)
	if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return nil
	}
	if err != nil {
		return err
	}
	s.Close()
	proved, _, err := ownedCoreService(m)
	if err != nil {
		// A fully protected, source-verified interrupted transaction still goes
		// through the existing lifecycle-locked recovery; preflight cannot turn
		// a recoverable transition into an orphan or authorize its mutations.
		if _, present, transitionErr := readCoreTransition(); transitionErr == nil && present {
			return nil
		}
		return fmt.Errorf("INSTALL_SERVICE_RECONCILIATION_REQUIRED: Windows 仍登記 USB Link 核心服務，但無法核對原安裝資料。請先檢查殘留服務狀態，再重新安裝；沒有停止、刪除或替換現有服務。 %w", err)
	}
	return proved.Close()
}

// Resume keeps authority in the native transaction verifier, rather than trying
// to authenticate the temporarily absent stable App as an ordinary launch.
func PreflightLocalInstallationForSetup(version string) error {
	if e := pendingInstallationRemoval(); e != nil {
		return e
	}
	if _, repair, e := inspectMissingAcceptedInstallation(version); e != nil {
		return e
	} else if repair {
		return nil
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	if exe, e := CurrentApplication(); e == nil && strings.EqualFold(exe, self) {
		return PreflightLocalInstallation()
	}
	t, ok, e := readInstallationTransaction()
	if e != nil {
		return e
	}
	if ok && t.Phase != InstallComplete && t.Phase != InstallRolledBack {
		sum, e := fileHash(self)
		u, ue := windows.GetCurrentProcessToken().GetTokenUser()
		if e != nil || ue != nil || t.Next.Version != version || t.Next.SHA != sum || u.User.Sid.String() != t.OwnerSID {
			return fmt.Errorf("INSTALL_PENDING_USE_ORIGINAL_SETUP")
		}
		return nil
	}
	return PreflightLocalInstallation()
}
