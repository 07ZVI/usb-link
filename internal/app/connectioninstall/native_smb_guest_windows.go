//go:build windows && amd64

package connectioninstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type smbGuestConfiguration struct {
	Name, SID       string
	OriginalFlags   uint32
	RemovedDeny     []string
	AddedNetwork    bool
	Enabled         bool
	SigningAdjusted bool
}

func smbGuestPath() (string, error) {
	d, e := SecurityDirectory()
	return filepath.Join(d, "native-smb-guest.json"), e
}
func loadSMBGuest() (smbGuestConfiguration, error) {
	var g smbGuestConfiguration
	p, e := smbGuestPath()
	if e != nil {
		return g, e
	}
	if e = readRemote(p, &g); os.IsNotExist(e) {
		return g, nil
	} else if e != nil {
		return g, e
	}
	if g.SID == "" || !strings.HasSuffix(g.SID, "-501") || g.Name == "" || len(g.RemovedDeny) > 2 {
		return g, fmt.Errorf("SMB_GUEST_RECEIPT_INVALID")
	}
	if _, e := windows.StringToSid(g.SID); e != nil {
		return g, fmt.Errorf("SMB_GUEST_RECEIPT_INVALID: %w", e)
	}
	for _, s := range g.RemovedDeny {
		if s != g.SID && s != "S-1-5-32-546" {
			return g, fmt.Errorf("SMB_GUEST_RECEIPT_INVALID")
		}
	}
	return g, nil
}
func nativeGuestSID() (string, error) {
	g, e := loadSMBGuest()
	if e != nil {
		return "", e
	}
	if g.SID == "" {
		return "", nil
	}
	if !g.Enabled {
		return "", fmt.Errorf("SMB_GUEST_RECOVERY_REQUIRED: 請先完成關閉訪客")
	}
	u, free, rc, e := querySMBUser(g.Name)
	if e != nil {
		return "", e
	}
	if rc != 0 {
		return "", fmt.Errorf("SMB_GUEST_QUERY_FAILED: %d", rc)
	}
	defer free()
	if u.SID.String() != g.SID || u.Flags&2 != 0 {
		return "", fmt.Errorf("SMB_GUEST_STATE_CHANGED: Windows 訪客身份已變更或停用")
	}
	return g.SID, nil
}
func localGuestIdentity() (string, string, error) {
	p, free := nativeNet.NewProc("NetUserModalsGet"), nativeNet.NewProc("NetApiBufferFree")
	if e := p.Find(); e != nil {
		return "", "", e
	}
	if e := free.Find(); e != nil {
		return "", "", e
	}
	var r *struct {
		Domain *uint16
		SID    *windows.SID
	}
	rc, _, _ := p.Call(0, 2, uintptr(unsafe.Pointer(&r)))
	if r != nil {
		defer free.Call(uintptr(unsafe.Pointer(r)))
	}
	if rc != 0 || r == nil || r.SID == nil {
		return "", "", fmt.Errorf("SMB_LOCAL_ACCOUNT_DOMAIN_UNAVAILABLE: %d", rc)
	}
	sid, e := windows.StringToSid(r.SID.String() + "-501")
	if e != nil {
		return "", "", e
	}
	name, _, _, e := sid.LookupAccount("")
	return name, sid.String(), e
}
func SetNativeSMBGuest(enabled bool) error { return setNativeSMBGuest(enabled, false) }

// Only the explicit local UI consent permits changing server-wide mandatory signing.
func SetNativeSMBGuestCompatible(enabled bool) error { return setNativeSMBGuest(enabled, true) }
func setNativeSMBGuest(enabled, compatible bool) error {
	nativeSMBOperationMu.Lock()
	defer nativeSMBOperationMu.Unlock()
	if e := nativeNet.NewProc("NetShareSetInfo").Find(); e != nil {
		return e
	}
	// Native Windows shares belonging to anyone else are never rewritten.
	if enabled {
		policy, e := readNativeSMBSecurity()
		if e != nil {
			return e
		}
		if policy.Encrypt {
			return fmt.Errorf("Windows SMB 要求加密，不能使用訪客；請使用專用帳戶。")
		}
		if policy.Signing && !compatible {
			return fmt.Errorf("Windows SMB 要求簽名，需在本機同意訪客相容設定。")
		}
	}
	if _, e := RefreshSharedFolders(); e != nil {
		return e
	}
	g, e := loadSMBGuest()
	if e != nil {
		return e
	}
	configure := func(on, compatible bool) error {
		nativeSMBMu.Lock()
		defer nativeSMBMu.Unlock()
		defer invalidateNativeSMB()
		return configureNativeGuest(on, compatible)
	}
	if !enabled {
		// If Guest was already enabled in Windows, restoring its original flags
		// does not revoke our shares. Remove their network grants first; still
		// restore the global policy when one folder's cleanup remains pending.
		if e = disableSMBGuest(func() error { return updateNativeGuestShares("") }, func() error { return configure(false, false) }); e != nil {
			return fmt.Errorf("Guest 關閉或部分共享權限恢復尚未完成，可重試或交由 Windows 管理：%w", e)
		}
		return nil
	}
	// Changing Guest is global, but it does not require tearing down dedicated
	// account shares or restoring/regranting their directory trees.
	e = configure(enabled, compatible)
	if e != nil {
		if enabled && !g.Enabled {
			e = errors.Join(e, configure(false, false))
		}
		return e
	}
	guest, e := nativeGuestSID()
	if e != nil {
		return e
	}
	if e = updateNativeGuestShares(guest); e != nil {
		return fmt.Errorf("Guest 設定已保存；部分共享權限尚未更新，可重試或交由 Windows 管理：%w", e)
	}
	return nil
}

func configureNativeGuest(enabled, compatible bool) error {
	g, e := loadSMBGuest()
	if e != nil {
		return e
	}
	p, e := smbGuestPath()
	if e != nil {
		return e
	}
	if enabled {
		policy, e := readNativeSMBSecurity()
		if e != nil {
			return e
		}
		if policy.Encrypt {
			return fmt.Errorf("Windows SMB 要求加密，不能使用訪客；請使用專用帳戶。")
		}
		if policy.Signing && !compatible {
			return fmt.Errorf("Windows SMB 要求簽名，需在本機同意訪客相容設定。")
		}
		if g.Enabled {
			if policy.Signing {
				return fmt.Errorf("Windows 簽名策略已再次要求簽名；請先關閉 Guest，再重新同意相容設定。")
			}
			return nil
		}
		if g.SID != "" {
			return fmt.Errorf("Guest 上次恢復未完成，請先關閉訪客後重試。")
		}
		name, sidText, e := localGuestIdentity()
		if e != nil {
			return e
		}
		u, free, rc, e := querySMBUser(name)
		if e != nil {
			return e
		}
		if rc != 0 {
			return fmt.Errorf("SMB_GUEST_QUERY_FAILED: %d", rc)
		}
		if u.SID.String() != sidText {
			free()
			return fmt.Errorf("SMB_GUEST_IDENTITY_CHANGED")
		}
		g = smbGuestConfiguration{Name: name, SID: sidText, OriginalFlags: u.Flags, SigningAdjusted: policy.Signing}
		free()
		sid, _ := windows.StringToSid(sidText)
		for _, identity := range []string{sidText, "S-1-5-32-546"} {
			s, _ := windows.StringToSid(identity)
			denied, e := hasLSARight(s, "SeDenyNetworkLogonRight")
			if e != nil {
				return e
			}
			if denied {
				g.RemovedDeny = append(g.RemovedDeny, identity)
			}
		}
		allow, e := hasLSARight(sid, "SeNetworkLogonRight")
		if e != nil {
			return e
		}
		g.AddedNetwork = !allow
		// Persist the exact restoration intent before changing the Guest identity.
		if e = writeRemote(p, g); e != nil {
			return e
		}
		if g.SigningAdjusted {
			if e = setNativeSMBSigning(false); e != nil {
				return e
			}
		}
		for _, identity := range g.RemovedDeny {
			s, _ := windows.StringToSid(identity)
			if e = setLSARights(s, []string{"SeDenyNetworkLogonRight"}, true); e != nil {
				return e
			}
		}
		if g.AddedNetwork {
			if e = setLSARights(sid, []string{"SeNetworkLogonRight"}, false); e != nil {
				return e
			}
		}
		if e = setSMBUserFlags(name, g.OriginalFlags&^2); e != nil {
			return e
		}
		g.Enabled = true
		return writeRemote(p, g)
	}
	if g.SID == "" {
		return nil
	}
	u, free, rc, e := querySMBUser(g.Name)
	if e != nil {
		return e
	}
	if rc != 0 {
		return fmt.Errorf("SMB_GUEST_QUERY_FAILED: %d", rc)
	}
	if u.SID.String() != g.SID {
		free()
		return fmt.Errorf("SMB_GUEST_IDENTITY_CHANGED")
	}
	flags := u.Flags
	free()
	// Restore just the original disabled bit, retaining other Windows changes.
	if e = setSMBUserFlags(g.Name, (flags&^2)|(g.OriginalFlags&2)); e != nil {
		return e
	}
	for _, identity := range g.RemovedDeny {
		s, _ := windows.StringToSid(identity)
		if e = setLSARights(s, []string{"SeDenyNetworkLogonRight"}, false); e != nil {
			return e
		}
	}
	if g.AddedNetwork {
		sid, _ := windows.StringToSid(g.SID)
		if e = setLSARights(sid, []string{"SeNetworkLogonRight"}, true); e != nil {
			return e
		}
	}
	if g.SigningAdjusted {
		if e = setNativeSMBSigning(true); e != nil {
			return fmt.Errorf("SMB 原簽名要求恢復未確認：%w", e)
		}
	}
	return os.Remove(p)
}

func NativeSMBGuestEnabled() bool {
	g, e := loadSMBGuest()
	if e != nil || !g.Enabled {
		return false
	}
	u, free, rc, e := querySMBUser(g.Name)
	if e != nil || rc != 0 {
		return false
	}
	defer free()
	return u.SID.String() == g.SID && u.Flags&2 == 0
}

type nativeSMBSecurity struct {
	Signing bool `json:"signing"`
	Encrypt bool `json:"encrypt"`
}

func nativeSMBSecurityCommand(script string) ([]byte, error) {
	system, e := windows.GetSystemDirectory()
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script)
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	return c.Output()
}
func readNativeSMBSecurity() (nativeSMBSecurity, error) {
	b, e := nativeSMBSecurityCommand(`$ErrorActionPreference='Stop';$s=Get-SmbServerConfiguration -ErrorAction Stop;if($null -eq $s.RequireSecuritySignature -or $null -eq $s.EncryptData){throw 'SMB security properties unavailable'};@{signing=[bool]$s.RequireSecuritySignature;encrypt=[bool]$s.EncryptData}|ConvertTo-Json -Compress`)
	if e == nil {
		var p struct {
			Signing *bool `json:"signing"`
			Encrypt *bool `json:"encrypt"`
		}
		if json.Unmarshal(b, &p) == nil && p.Signing != nil && p.Encrypt != nil {
			return nativeSMBSecurity{*p.Signing, *p.Encrypt}, nil
		}
	}
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, registry.QUERY_VALUE)
	if e != nil {
		return nativeSMBSecurity{}, e
	}
	defer k.Close()
	v, _, e := k.GetIntegerValue("RequireSecuritySignature")
	if e != nil {
		return nativeSMBSecurity{}, fmt.Errorf("無法確認 Windows SMB 安全策略，未調整訪客；請檢查系統元件。")
	}
	encrypt, _, e := k.GetIntegerValue("EncryptData")
	if e != nil && e != registry.ErrNotExist {
		return nativeSMBSecurity{}, e
	}
	return nativeSMBSecurity{v != 0, encrypt != 0}, nil
}
func setNativeSMBSigning(required bool) error {
	value := "$false"
	if required {
		value = "$true"
	}
	_, e := nativeSMBSecurityCommand(`$ErrorActionPreference='Stop';Set-SmbServerConfiguration -RequireSecuritySignature ` + value + ` -Force -ErrorAction Stop`)
	if e != nil {
		return fmt.Errorf("Windows SMB 簽名設定未完成：%w", e)
	}
	policy, e := readNativeSMBSecurity()
	if e != nil {
		return e
	}
	if policy.Signing != required {
		return fmt.Errorf("Windows SMB 簽名設定未生效；可能受系統策略管理。")
	}
	return nil
}
