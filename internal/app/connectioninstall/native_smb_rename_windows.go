//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func smbAccountRenamePath() (string, error) {
	d, err := SecurityDirectory()
	return filepath.Join(d, "native-smb-account-rename.json"), err
}

// Called under smbAccountMu. Recovery only completes the protected receipt for
// a name already changed by the explicit local action. It never renames another
// account, changes a password or replaces an account created outside USB Link.
func recoverSMBAccountRename(a *smbAccount) error {
	p, err := smbAccountRenamePath()
	if err != nil {
		return err
	}
	var j smbAccountRename
	if err = readRemote(p, &j); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	name, err := resolveSMBAccountRename(a.Name, a.SID, j, func(name, sid string) error {
		return verifySMBAccount(smbAccount{Name: name, SID: sid})
	})
	if err != nil {
		return err
	}
	if name == j.To {
		updated := *a
		updated.Name = name
		state, err := smbAccountPath()
		if err != nil {
			return err
		}
		if err = writeRemote(state, updated); err != nil {
			return err
		}
		*a = updated
	}
	// Either the receipt matches the renamed identity, or Windows never applied
	// the rename and the original owned identity remains intact.
	return os.Remove(p)
}

// Rename retains the SID, password, logon restrictions and share/root ACLs.
// The local UI confirms this action; the maintenance API cannot invoke it.
func RenameSMBAccount(name string) error {
	if err := ValidateSMBAccountName(name); err != nil {
		return err
	}
	smbAccountMu.Lock()
	defer smbAccountMu.Unlock()
	a, err := loadSMBAccountLocked()
	if err != nil {
		return err
	}
	if err = verifySMBAccountReady(a); err != nil {
		return err
	}
	if strings.EqualFold(name, a.Name) {
		return nil
	}
	u, free, rc, err := querySMBUser(name)
	if u != nil {
		free()
	}
	if err != nil {
		return err
	}
	if rc != 2221 {
		return fmt.Errorf("名稱已被 Windows 帳戶使用，未覆蓋或修改該帳戶。")
	}
	p, err := smbAccountRenamePath()
	if err != nil {
		return err
	}
	if err = writeRemote(p, smbAccountRename{From: a.Name, To: name, SID: a.SID}); err != nil {
		return err
	}
	proc := nativeNet.NewProc("NetUserSetInfo")
	if err = proc.Find(); err != nil {
		return err
	}
	r := struct{ Name *uint16 }{windows.StringToUTF16Ptr(name)}
	var field uint32
	rc64, _, _ := proc.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(a.Name))), 0, uintptr(unsafe.Pointer(&r)), uintptr(unsafe.Pointer(&field)))
	runtime.KeepAlive(r)
	if rc64 != 0 {
		if cleanup := recoverSMBAccountRename(&a); cleanup != nil {
			return cleanup
		}
		return fmt.Errorf("SMB_ACCOUNT_RENAME_FAILED: %d field=%d", rc64, field)
	}
	if err = recoverSMBAccountRename(&a); err != nil {
		return err
	}
	if a.Name != name {
		return fmt.Errorf("SMB_ACCOUNT_RENAME_READBACK_FAILED")
	}
	if err = verifySMBAccountReady(a); err != nil {
		return err
	}
	invalidateNativeSMB()
	return nil
}
