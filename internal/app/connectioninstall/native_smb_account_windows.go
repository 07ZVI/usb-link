//go:build windows && amd64

package connectioninstall

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const smbAccountName = "USBLink"
const smbAccountMarker = "USB Link SMB-only account / v1"

type smbAccount struct {
	Name, SID       string
	Password        []byte
	PendingPassword []byte
}
type SMBAccountView struct {
	Exists                 bool   `json:"exists"`
	Username               string `json:"username"`
	LocalName              string `json:"local_name"`
	Password               string `json:"password,omitempty"`
	Problem                string `json:"problem,omitempty"`
	AuthenticationVerified bool   `json:"authentication_verified,omitempty"`
}

var smbAccountMu sync.Mutex

type userInfo1 struct {
	Name, Password         *uint16
	PasswordAge, Privilege uint32
	Home, Comment          *uint16
	Flags                  uint32
	Script                 *uint16
}
type userInfo23 struct {
	Name, FullName, Comment *uint16
	Flags                   uint32
	SID                     *windows.SID
}

func smbAccountPath() (string, error) {
	d, e := SecurityDirectory()
	return filepath.Join(d, "native-smb-account.json"), e
}
func protectSMBPassword(b []byte, decrypt bool) ([]byte, error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, e
	}
	if u.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		var result []byte
		e = WithBoundCoreUser(func() error {
			var e error
			result, e = protectSMBPasswordCurrentUser(b, decrypt)
			return e
		})
		return result, e
	}
	return protectSMBPasswordCurrentUser(b, decrypt)
}
func protectSMBPasswordCurrentUser(b []byte, decrypt bool) ([]byte, error) {
	if len(b) == 0 || len(b) > 8192 {
		return nil, fmt.Errorf("SMB_PASSWORD_BLOB_INVALID")
	}
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	var e error
	if decrypt {
		e = windows.CryptUnprotectData(&in, nil, nil, 0, nil, 1, &out)
	} else {
		e = windows.CryptProtectData(&in, windows.StringToUTF16Ptr("USB Link SMB credentials"), nil, 0, nil, 1, &out)
	}
	if e != nil {
		return nil, e
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	if out.Size == 0 || out.Size > 8192 || out.Data == nil {
		return nil, fmt.Errorf("SMB_PASSWORD_PROTECTION_FAILED")
	}
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}
func loadSMBAccount() (smbAccount, error) {
	smbAccountMu.Lock()
	defer smbAccountMu.Unlock()
	return loadSMBAccountLocked()
}
func loadSMBAccountLocked() (smbAccount, error) {
	var a smbAccount
	p, e := smbAccountPath()
	if e != nil {
		return a, e
	}
	if e = readRemote(p, &a); e != nil {
		return a, e
	}
	if ValidateSMBAccountName(a.Name) != nil || a.SID == "" || len(a.Password) == 0 || len(a.Password) > 8192 || len(a.PendingPassword) > 8192 {
		return a, fmt.Errorf("SMB_ACCOUNT_RECEIPT_INVALID")
	}
	if e = recoverSMBAccountRename(&a); e != nil {
		return a, e
	}
	if e = verifySMBAccount(a); e != nil {
		return a, e
	}
	return a, nil
}
func querySMBUser(name string) (*userInfo23, func(), uint32, error) {
	p, free := nativeNet.NewProc("NetUserGetInfo"), nativeNet.NewProc("NetApiBufferFree")
	if e := p.Find(); e != nil {
		return nil, nil, 0, e
	}
	if e := free.Find(); e != nil {
		return nil, nil, 0, e
	}
	var u *userInfo23
	rc, _, _ := p.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 23, uintptr(unsafe.Pointer(&u)))
	cleanup := func() {
		if u != nil {
			free.Call(uintptr(unsafe.Pointer(u)))
		}
	}
	if rc != 0 {
		cleanup()
		return nil, nil, uint32(rc), nil
	}
	if u == nil || u.SID == nil {
		cleanup()
		return nil, nil, 0, fmt.Errorf("SMB_ACCOUNT_READBACK_INVALID")
	}
	return u, cleanup, 0, nil
}
func verifySMBAccount(a smbAccount) error {
	u, free, rc, e := querySMBUser(a.Name)
	if e != nil {
		return e
	}
	if rc != 0 {
		return fmt.Errorf("SMB_ACCOUNT_QUERY_FAILED: %d", rc)
	}
	defer free()
	if u.Comment == nil || windows.UTF16PtrToString(u.Comment) != smbAccountMarker || u.SID.String() != a.SID {
		return fmt.Errorf("SMB_ACCOUNT_OWNERSHIP_CHANGED")
	}
	return nil
}
func NativeSMBAccountView(reveal bool) SMBAccountView {
	smbAccountMu.Lock()
	defer smbAccountMu.Unlock()
	return nativeSMBAccountViewLocked(reveal, false)
}

// Explicit local reads validate the stored credential without returning it to
// diagnostics. Background readiness checks must never attempt authentication.
func ReadNativeSMBAccount(reveal bool) SMBAccountView {
	smbAccountMu.Lock()
	defer smbAccountMu.Unlock()
	v := nativeSMBAccountViewLocked(reveal, true)
	recordSMBAccountRead(v)
	return v
}

func nativeSMBAccountViewLocked(reveal, checkPassword bool) SMBAccountView {
	a, e := loadSMBAccountLocked()
	if e != nil {
		_, u, _ := nativeUserIdentity()
		problem := ""
		if !os.IsNotExist(e) {
			problem = e.Error()
		}
		return SMBAccountView{Username: u, LocalName: smbAccountName, Problem: problem}
	}
	sid, _ := windows.StringToSid(a.SID)
	name, domain, _, e := sid.LookupAccount("")
	v := SMBAccountView{Exists: e == nil, Username: domain + "\\" + name, LocalName: name}
	if e != nil {
		v.Problem = "SMB 帳戶名稱無法讀取：" + e.Error()
		return v
	}
	if len(a.PendingPassword) != 0 {
		v.Problem = "密碼更新曾中斷；請保存新密碼以完成恢復，暫不顯示不確定的舊密碼。"
		return v
	}
	if e := verifySMBAccountReady(a); e != nil {
		v.Problem = e.Error()
	}
	if reveal || checkPassword && v.Problem == "" {
		if p, e := protectSMBPassword(a.Password, true); e == nil {
			if checkPassword && v.Problem == "" {
				if e = verifySMBNetworkCredential(a, p); e != nil {
					v.Problem = e.Error()
				} else {
					v.AuthenticationVerified = true
				}
			}
			if reveal && v.Problem == "" {
				v.Password = string(p)
			}
			clear(p)
		} else {
			if v.Problem != "" {
				v.Problem += "\n"
			}
			v.Problem += "SMB 已保存密碼無法讀取：" + e.Error()
		}
	}
	return v
}
func nativeShareSID() (string, error) {
	a, e := loadSMBAccount()
	if os.IsNotExist(e) {
		sid, _, e := nativeUserIdentity()
		return sid, e
	}
	if e != nil {
		return "", e
	}
	if len(a.PendingPassword) != 0 {
		return "", fmt.Errorf("SMB_PASSWORD_RECOVERY_REQUIRED: 請保存新密碼以恢復專用帳戶")
	}
	if e = verifySMBAccountReady(a); e != nil {
		return "", e
	}
	return a.SID, nil
}

// The caller is a local UI action. Generated credentials go only to the local
// desktop pipe, never diagnostics or network maintenance responses.
// Serialize share suspension, identity mutation and republication with every
// other native SMB operation, including callers outside the desktop window.
func UpdateNativeSMBAccount(reset bool, password, name string) (bool, error) {
	if password != "" {
		if e := ValidateSMBPassword(password); e != nil {
			return false, e
		}
	}
	if name != "" {
		if e := ValidateSMBAccountName(name); e != nil {
			return false, e
		}
	}
	nativeSMBOperationMu.Lock()
	defer nativeSMBOperationMu.Unlock()
	return updateNativeSMBAccountLocked(reset, password, name)
}

func updateNativeSMBAccountLocked(reset bool, password, name string) (bool, error) {
	// A password reset retains the SID and every share/ACL. Changing a password
	// must not traverse directory trees or depend on removable-drive availability.
	if reset {
		err := CreateSMBAccount(true, password, name)
		return err == nil, err
	}
	active := NativeSMBStatus().Enabled
	if e := setNativeSMB(false); e != nil {
		if active {
			return false, errors.Join(e, setNativeSMB(true))
		}
		return false, e
	}
	saved := false
	err := changeSMBIdentity(active, func() error {
		e := CreateSMBAccount(reset, password, name)
		saved = e == nil
		return e
	}, nil, func() error { return setNativeSMB(true) })
	return saved, err
}

func CreateSMBAccount(reset bool, customPassword string, customName string) error {
	if customName == "" {
		customName = smbAccountName
	}
	if e := ValidateSMBAccountName(customName); e != nil {
		return e
	}
	if customPassword != "" {
		if e := ValidateSMBPassword(customPassword); e != nil {
			return e
		}
	}
	smbAccountMu.Lock()
	defer smbAccountMu.Unlock()
	p, e := smbAccountPath()
	if e != nil {
		return e
	}
	a, e := loadSMBAccountLocked()
	create := os.IsNotExist(e)
	if !create && e != nil {
		return e
	}
	if !create && !reset {
		if len(a.PendingPassword) != 0 {
			return fmt.Errorf("SMB_PASSWORD_RECOVERY_REQUIRED: 請使用保存新密碼完成恢復")
		}
		if customPassword != "" {
			return fmt.Errorf("專用帳戶已存在，請使用「保存新密碼」。")
		}
		return completeSMBAccount(a)
	}
	if create && reset {
		return fmt.Errorf("SMB_ACCOUNT_NOT_CREATED")
	}
	password := []byte(customPassword)
	if len(password) == 0 {
		var b [18]byte
		if _, e = rand.Read(b[:]); e != nil {
			return e
		}
		password = []byte("Usb!" + hex.EncodeToString(b[:]))
	}
	defer clear(password)
	encrypted, e := protectSMBPassword(password, false)
	if e != nil {
		return e
	}
	if create {
		u, free, rc, e := querySMBUser(customName)
		if u != nil {
			free()
		}
		if e != nil {
			return e
		}
		if rc != 2221 {
			return fmt.Errorf("SMB_ACCOUNT_NAME_ALREADY_EXISTS")
		}
		// Create disabled. Failure before rights/receipt completion cannot leave
		// a usable account with unknown credentials or interactive logon rights.
		encoded := windows.StringToUTF16(string(password))
		defer clear(encoded)
		r := userInfo1{Name: windows.StringToUTF16Ptr(customName), Password: &encoded[0], Privilege: 1, Comment: windows.StringToUTF16Ptr(smbAccountMarker), Flags: 1 | 2 | 0x200 | 0x10000}
		proc := nativeNet.NewProc("NetUserAdd")
		if e = proc.Find(); e != nil {
			return e
		}
		var field uint32
		result, _, _ := proc.Call(0, 1, uintptr(unsafe.Pointer(&r)), uintptr(unsafe.Pointer(&field)))
		runtime.KeepAlive(r)
		if result != 0 {
			return fmt.Errorf("SMB_ACCOUNT_CREATE_FAILED: %d field=%d", result, field)
		}
		u, free, rc, e = querySMBUser(customName)
		if e != nil {
			return e
		}
		if rc != 0 {
			return fmt.Errorf("SMB_ACCOUNT_READBACK_FAILED: %d", rc)
		}
		a = smbAccount{Name: customName, SID: u.SID.String(), Password: encrypted}
		free()
		if e = writeRemote(p, a); e != nil {
			return e
		}
		if e = completeSMBAccount(a); e != nil {
			return e
		}
	} else {
		oldPassword, e := protectSMBPassword(a.Password, true)
		if e != nil {
			return e
		}
		defer clear(oldPassword)
		if e = completeSMBAccount(a); e != nil {
			return e
		}
		pending := a
		pending.PendingPassword = encrypted
		updated := a
		updated.Password, updated.PendingPassword = encrypted, nil
		e = commitSMBPassword(func() error { return writeRemote(p, pending) }, func() error { return setSMBPassword(a.Name, password) }, func() error { return writeRemote(p, updated) }, func() error {
			if er := verifySMBAccount(a); er != nil {
				return er
			}
			er := setSMBPassword(a.Name, oldPassword)
			if er == nil {
				a.PendingPassword = nil
				er = writeRemote(p, a)
			}
			if er != nil {
				// Retain the encrypted pending journal and refuse publishing credentials
				// whose password state cannot be confirmed. Never disable a foreign SID.
				if verifySMBAccount(a) == nil {
					u, free, rc, queryErr := querySMBUser(a.Name)
					if queryErr == nil && rc == 0 {
						flags := u.Flags
						free()
						_ = setSMBUserFlags(a.Name, flags|2)
					}
				}
				return fmt.Errorf("SMB_PASSWORD_RECOVERY_REQUIRED: %w", er)
			}
			return nil
		})
		if e != nil {
			return e
		}

	}
	invalidateNativeSMB()
	return nil
}
func setSMBPassword(name string, password []byte) error {
	proc := nativeNet.NewProc("NetUserSetInfo")
	if e := proc.Find(); e != nil {
		return e
	}
	encoded := windows.StringToUTF16(string(password))
	defer clear(encoded)
	r := struct{ Password *uint16 }{&encoded[0]}
	var field uint32
	rc, _, _ := proc.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 1003, uintptr(unsafe.Pointer(&r)), uintptr(unsafe.Pointer(&field)))
	runtime.KeepAlive(r)
	if rc != 0 {
		return fmt.Errorf("SMB_ACCOUNT_RESET_FAILED: %d", rc)
	}
	return nil
}

var smbRestrictedRights = []string{"SeDenyInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight", "SeDenyBatchLogonRight", "SeDenyServiceLogonRight", "SeNetworkLogonRight"}

func completeSMBAccount(a smbAccount) error {
	if e := verifySMBOrdinaryAccount(a); e != nil {
		return e
	}
	sid, e := windows.StringToSid(a.SID)
	if e != nil {
		return e
	}
	if e = setLSARights(sid, smbRestrictedRights, false); e != nil {
		return e
	}
	for _, right := range smbRestrictedRights {
		ok, er := hasLSARight(sid, right)
		if er != nil {
			return er
		}
		if !ok {
			return fmt.Errorf("SMB_ACCOUNT_LOGON_POLICY_READBACK_FAILED")
		}
	}
	u, free, rc, e := querySMBUser(a.Name)
	if e != nil {
		return e
	}
	if rc != 0 {
		return fmt.Errorf("SMB_ACCOUNT_QUERY_FAILED: %d", rc)
	}
	flags := u.Flags
	free()
	if e = setSMBUserFlags(a.Name, (flags|0x10000)&^uint32(2)); e != nil {
		return e
	}
	return verifySMBAccountReady(a)
}
func verifySMBAccountReady(a smbAccount) error {
	if e := verifySMBOrdinaryAccount(a); e != nil {
		return e
	}
	u, free, rc, e := querySMBUser(a.Name)
	if e != nil {
		return e
	}
	if rc != 0 {
		return fmt.Errorf("SMB_ACCOUNT_QUERY_FAILED: %d", rc)
	}
	flags := u.Flags
	free()
	if flags&2 != 0 {
		return fmt.Errorf("SMB_ACCOUNT_DISABLED: 請重新建立／重置專用帳戶以恢復設定")
	}
	sid, e := windows.StringToSid(a.SID)
	if e != nil {
		return e
	}
	for _, right := range smbRestrictedRights {
		ok, er := hasLSARight(sid, right)
		if er != nil {
			return er
		}
		if !ok {
			return fmt.Errorf("SMB_ACCOUNT_LOGON_POLICY_CHANGED")
		}
	}
	return nil
}
func verifySMBOrdinaryAccount(a smbAccount) error {
	if e := verifySMBAccount(a); e != nil {
		return e
	}
	proc := nativeNet.NewProc("NetUserGetLocalGroups")
	if e := proc.Find(); e != nil {
		return e
	}
	var rows **uint16
	var count, total uint32
	rc, _, _ := proc.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(a.Name))), 0, 1, uintptr(unsafe.Pointer(&rows)), uintptr(^uint32(0)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&total)))
	if rows != nil {
		defer nativeNet.NewProc("NetApiBufferFree").Call(uintptr(unsafe.Pointer(rows)))
	}
	if rc != 0 || count > 1024 || count > 0 && rows == nil {
		return fmt.Errorf("SMB_ACCOUNT_GROUP_QUERY_FAILED: %d", rc)
	}
	if count > 0 {
		for _, name := range unsafe.Slice(rows, int(count)) {
			if name == nil {
				return fmt.Errorf("SMB_ACCOUNT_GROUP_INVALID")
			}
			sid, _, _, e := windows.LookupSID("", windows.UTF16PtrToString(name))
			if e != nil {
				return e
			}
			if sid.String() == "S-1-5-32-544" {
				return fmt.Errorf("SMB_ACCOUNT_IS_ADMINISTRATOR")
			}
		}
	}
	return nil
}
func setSMBUserFlags(name string, flags uint32) error {
	proc := nativeNet.NewProc("NetUserSetInfo")
	if e := proc.Find(); e != nil {
		return e
	}
	var field uint32
	rc, _, _ := proc.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 1008, uintptr(unsafe.Pointer(&flags)), uintptr(unsafe.Pointer(&field)))
	if rc != 0 {
		return fmt.Errorf("SMB_ACCOUNT_FLAGS_FAILED: %d", rc)
	}
	return nil
}

func removeSMBAccount() error {
	smbAccountMu.Lock()
	defer smbAccountMu.Unlock()
	p, e := smbAccountPath()
	if e != nil {
		return e
	}
	var a smbAccount
	if e = readRemote(p, &a); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	if ValidateSMBAccountName(a.Name) != nil || a.SID == "" {
		return fmt.Errorf("SMB_ACCOUNT_RECEIPT_INVALID")
	}
	if e = recoverSMBAccountRename(&a); e != nil {
		return e
	}
	sid, e := windows.StringToSid(a.SID)
	if e != nil {
		return e
	}
	u, free, rc, e := querySMBUser(a.Name)
	if e != nil {
		return e
	}
	if rc != 0 && rc != 2221 {
		return fmt.Errorf("SMB_ACCOUNT_QUERY_FAILED: %d", rc)
	}
	if rc == 0 {
		owned := u.SID.String() == a.SID && u.Comment != nil && windows.UTF16PtrToString(u.Comment) == smbAccountMarker
		free()
		if !owned {
			return fmt.Errorf("SMB_ACCOUNT_OWNERSHIP_CHANGED")
		}
		proc := nativeNet.NewProc("NetUserDel")
		if e = proc.Find(); e != nil {
			return e
		}
		rc, _, _ := proc.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(a.Name))))
		if rc != 0 && rc != 2221 {
			return fmt.Errorf("SMB_ACCOUNT_REMOVE_FAILED: %d", rc)
		}
	}
	// Rights are keyed by the retired SID, never by a potentially reused name.
	for _, right := range smbRestrictedRights {
		present, er := hasLSARight(sid, right)
		if er != nil {
			return er
		}
		if present {
			if e = setLSARights(sid, []string{right}, true); e != nil {
				return e
			}
		}
	}
	return os.Remove(p)
}

type lsaString struct {
	Length, MaximumLength uint16
	Buffer                *uint16
}
type lsaAttributes struct {
	Length     uint32
	Root       uintptr
	Name       *lsaString
	Attributes uint32
	SD, QOS    uintptr
}

func openSMBPolicy() (uintptr, error) {
	api := windows.NewLazySystemDLL("advapi32.dll")
	p := api.NewProc("LsaOpenPolicy")
	if e := p.Find(); e != nil {
		return 0, e
	}
	a := lsaAttributes{Length: uint32(unsafe.Sizeof(lsaAttributes{}))}
	var h uintptr
	rc, _, _ := p.Call(0, uintptr(unsafe.Pointer(&a)), 0x800|0x10, uintptr(unsafe.Pointer(&h)))
	if rc != 0 {
		return 0, fmt.Errorf("SMB_ACCOUNT_POLICY_FAILED: %x", rc)
	}
	return h, nil
}
func lsaStrings(names []string) []lsaString {
	rows := make([]lsaString, 0, len(names))
	for _, n := range names {
		b := windows.StringToUTF16(n)
		rows = append(rows, lsaString{uint16((len(b) - 1) * 2), uint16(len(b) * 2), &b[0]})
	}
	return rows
}
func setLSARights(sid *windows.SID, names []string, remove bool) error {
	h, e := openSMBPolicy()
	if e != nil {
		return e
	}
	api := windows.NewLazySystemDLL("advapi32.dll")
	defer api.NewProc("LsaClose").Call(h)
	rows := lsaStrings(names)
	if len(rows) == 0 {
		return nil
	}
	var rc uintptr
	if remove {
		rc, _, _ = api.NewProc("LsaRemoveAccountRights").Call(h, uintptr(unsafe.Pointer(sid)), 0, uintptr(unsafe.Pointer(&rows[0])), uintptr(len(rows)))
	} else {
		rc, _, _ = api.NewProc("LsaAddAccountRights").Call(h, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&rows[0])), uintptr(len(rows)))
	}
	runtime.KeepAlive(rows)
	runtime.KeepAlive(sid)
	if rc != 0 {
		return fmt.Errorf("SMB_ACCOUNT_LOGON_POLICY_FAILED: %x", rc)
	}
	return nil
}
func hasLSARight(sid *windows.SID, name string) (bool, error) {
	h, e := openSMBPolicy()
	if e != nil {
		return false, e
	}
	api := windows.NewLazySystemDLL("advapi32.dll")
	defer api.NewProc("LsaClose").Call(h)
	var rows *lsaString
	var count uint32
	rc, _, _ := api.NewProc("LsaEnumerateAccountRights").Call(h, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&rows)), uintptr(unsafe.Pointer(&count)))
	if rows != nil {
		defer api.NewProc("LsaFreeMemory").Call(uintptr(unsafe.Pointer(rows)))
	}
	if uint32(rc) == 0xc0000034 {
		return false, nil
	}
	if rc != 0 || count > 256 || count > 0 && rows == nil {
		return false, fmt.Errorf("SMB_ACCOUNT_RIGHTS_QUERY_FAILED: %x", rc)
	}
	if count > 0 {
		for _, r := range unsafe.Slice(rows, int(count)) {
			if r.Length > 1024 || r.Length%2 != 0 || r.Buffer == nil {
				return false, fmt.Errorf("SMB_ACCOUNT_RIGHTS_INVALID")
			}
			if strings.EqualFold(windows.UTF16ToString(unsafe.Slice(r.Buffer, int(r.Length/2))), name) {
				return true, nil
			}
		}
	}
	return false, nil
}
