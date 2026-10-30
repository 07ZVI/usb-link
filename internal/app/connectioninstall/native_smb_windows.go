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
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"log"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/security/usbgateway"
	"suhang/usbnet/internal/sharing/fileshare"
)

const nativeSMBMarker = "USB Link native SMB / v1 / "

type NativeSMBInfo struct {
	Ready      bool   `json:"ready"`
	Enabled    bool   `json:"enabled"`
	Shared     int    `json:"shared_folders"`
	ConnectURL string `json:"connect_url"`
	Username   string `json:"username,omitempty"`
	Problem    string `json:"problem,omitempty"`
	Busy       bool   `json:"busy,omitempty"`
}
type nativeShare502 struct {
	Name                              *uint16
	Type                              uint32
	Remark                            *uint16
	Permissions, MaxUses, CurrentUses uint32
	Path, Password                    *uint16
	Reserved                          uint32
	SD                                *windows.SECURITY_DESCRIPTOR
}

var nativeSMBMu sync.Mutex
var nativeSMBOperationMu sync.Mutex
var nativeSMBCache struct {
	sync.Mutex
	At   time.Time
	Info NativeSMBInfo
}
var nativeNet = windows.NewLazySystemDLL("netapi32.dll")

func nativeSMBPath() (string, error) {
	d, e := SecurityDirectory()
	return filepath.Join(d, "native-smb.json"), e
}
func loadNativeSMB() (nativeSMBConfiguration, error) {
	c := nativeSMBConfiguration{Version: 1}
	p, e := nativeSMBPath()
	if e != nil {
		return c, e
	}
	if e = readNativeSMBState(p, &c); os.IsNotExist(e) {
		return c, nil
	} else if e != nil {
		return c, e
	}
	if (c.Version != 1 && c.Version != 2 && c.Version != 3) || c.Version != nativeSMBStateVersion(c) || len(c.Shares) > 32 || len(c.Access) > 32 || len(c.Names) > 32 {
		return c, fmt.Errorf("NATIVE_SMB_CONFIGURATION_INVALID")
	}
	seen, ids := map[string]bool{}, map[string]bool{}
	for _, p := range c.Access {
		if !fileshare.ValidFolderID(p.ID) || !filepath.IsAbs(p.Path) || p.FileID == "" || !validSMBAccess(p.Account) || p.Account == "" || !validSMBAccess(p.Guest) || p.Guest == "" || ids[p.ID] {
			return c, fmt.Errorf("NATIVE_SMB_ACCESS_SETTINGS_INVALID")
		}
		ids[p.ID] = true
	}
	for _, b := range c.Names {
		if !fileshare.ValidFolderID(b.ID) || !filepath.IsAbs(b.Path) || !validNativeSMBShareName(nativeSMBShare{ID: b.ID, Path: b.Path, Name: b.Name, NamePath: b.NamePath}) {
			return c, fmt.Errorf("NATIVE_SMB_NAME_BINDING_INVALID")
		}
	}
	ids = map[string]bool{}
	for _, s := range c.Shares {
		if !validSMBAccess(s.AccountAccess) || !validSMBAccess(s.GuestAccess) || !validSMBAccess(s.NextAccountAccess) || !validSMBAccess(s.NextGuestAccess) || s.AccessUpdate && s.GuestUpdate || !s.AccessUpdate && (s.NextAccountAccess != "" || s.NextGuestAccess != "") {
			return c, fmt.Errorf("NATIVE_SMB_ACCESS_JOURNAL_INVALID")
		}
		if !fileshare.ValidFolderID(s.ID) || !validNativeSMBShareName(s) || !validSMBMigration(s.ID, s.Name, s.Path, s.MigrationName, s.MigrationFileID, s.AccessUpdate || s.GuestUpdate) || !filepath.IsAbs(s.Path) || seen[strings.ToLower(s.Name)] || ids[s.ID] {
			return c, fmt.Errorf("NATIVE_SMB_RECEIPT_INVALID")
		}
		if _, e = windows.StringToSid(s.SID); e != nil {
			return c, e
		}
		if s.NextGuestSID != "" {
			if !s.GuestUpdate {
				return c, fmt.Errorf("NATIVE_SMB_GUEST_JOURNAL_INVALID")
			}
			if _, e = windows.StringToSid(s.NextGuestSID); e != nil {
				return c, e
			}
		}
		if s.GuestSID != "" {
			if _, e = windows.StringToSid(s.GuestSID); e != nil {
				return c, e
			}
		}
		seen[strings.ToLower(s.Name)] = true
		if s.MigrationName != "" {
			if seen[strings.ToLower(s.MigrationName)] {
				return c, fmt.Errorf("NATIVE_SMB_MIGRATION_NAME_CONFLICT")
			}
			seen[strings.ToLower(s.MigrationName)] = true
		}
		ids[s.ID] = true
	}
	return c, nil
}
func saveNativeSMB(c nativeSMBConfiguration) error {
	c.Version = nativeSMBStateVersion(c)
	p, e := nativeSMBPath()
	if e != nil {
		return e
	}
	return writeRemote(p, c)
}
func nativeUserIdentity() (sid, username string, err error) {
	user, release, e := shareUser()
	if e != nil {
		return "", "", e
	}
	defer release()
	e = user(func() error {
		var t windows.Token
		if e := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &t); e != nil {
			return e
		}
		defer t.Close()
		u, e := t.GetTokenUser()
		if e != nil {
			return e
		}
		sid = u.User.Sid.String()
		a, d, _, e := u.User.Sid.LookupAccount("")
		if e != nil {
			return e
		}
		username = d + "\\" + a
		return nil
	})
	return sid, username, e
}
func nativeSD(sid string, guest string) (*windows.SECURITY_DESCRIPTOR, error) {
	if _, e := windows.StringToSid(sid); e != nil {
		return nil, e
	}
	text := "D:P(A;;FA;;;" + sid + ")"
	if guest != "" {
		if _, e := windows.StringToSid(guest); e != nil {
			return nil, e
		}
		text += "(A;;FA;;;" + guest + ")"
	}
	return windows.SecurityDescriptorFromString(text)
}
func getNativeShare(name string) (*nativeShare502, func(), uint32, error) {
	proc, free := nativeNet.NewProc("NetShareGetInfo"), nativeNet.NewProc("NetApiBufferFree")
	if e := proc.Find(); e != nil {
		return nil, nil, 0, e
	}
	if e := free.Find(); e != nil {
		return nil, nil, 0, e
	}
	var b *nativeShare502
	rc, _, _ := proc.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 502, uintptr(unsafe.Pointer(&b)))
	cleanup := func() {
		if b != nil {
			free.Call(uintptr(unsafe.Pointer(b)))
		}
	}
	if rc != 0 {
		cleanup()
		return nil, nil, uint32(rc), nil
	}
	if b == nil {
		return nil, nil, 0, fmt.Errorf("NATIVE_SMB_EMPTY_READBACK")
	}
	return b, cleanup, 0, nil
}
func ownedNativeShare(want nativeSMBShare, got *nativeShare502) bool {
	if got == nil || got.Name == nil || got.Path == nil || got.Remark == nil || got.SD == nil || got.Type != 0 {
		return false
	}
	sd, e := nativeShareSD(want)
	identity := strings.EqualFold(windows.UTF16PtrToString(got.Name), want.Name) && strings.EqualFold(filepath.Clean(windows.UTF16PtrToString(got.Path)), filepath.Clean(want.Path)) && windows.UTF16PtrToString(got.Remark) == nativeSMBMarker+want.ID
	if !identity || e != nil {
		return false
	}
	if sameNativeSMBShareACL(got.SD, sd) {
		return true
	}
	if want.GuestUpdate {
		next := want
		next.GuestSID = want.NextGuestSID
		target, e := nativeShareSD(next)
		return e == nil && sameNativeSMBShareACL(got.SD, target)
	}
	if want.AccessUpdate {
		next := want
		next.AccountAccess, next.GuestAccess = want.NextAccountAccess, want.NextGuestAccess
		target, e := nativeShareSD(next)
		return e == nil && sameNativeSMBShareACL(got.SD, target)
	}
	return false
}
func deleteNativeShareExact(want nativeSMBShare) error {
	got, free, rc, e := getNativeShare(want.Name)
	if e != nil {
		return e
	}
	if rc == 2310 {
		return nil
	}
	if rc != 0 {
		return fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc)
	}
	ok := ownedNativeShare(want, got)
	free()
	if !ok {
		return fmt.Errorf("NATIVE_SMB_CHANGED_IN_WINDOWS: %s", want.Name)
	}
	p := nativeNet.NewProc("NetShareDel")
	if e = p.Find(); e != nil {
		return e
	}
	r, _, _ := p.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(want.Name))), 0)
	if r != 0 && r != 2310 {
		return fmt.Errorf("NATIVE_SMB_REMOVE_FAILED: %d", r)
	}
	return nil
}
func addNativeShare(want nativeSMBShare) error {
	got, free, rc, e := getNativeShare(want.Name)
	if e != nil {
		return e
	}
	if rc == 0 {
		ok := ownedNativeShare(want, got)
		free()
		if ok {
			return nil
		}
		return fmt.Errorf("NATIVE_SMB_NAME_CONFLICT: %s", want.Name)
	}
	if rc != 2310 {
		return fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc)
	}
	sd, e := nativeShareSD(want)
	if e != nil {
		return e
	}
	r := nativeShare502{Name: windows.StringToUTF16Ptr(want.Name), Remark: windows.StringToUTF16Ptr(nativeSMBMarker + want.ID), Path: windows.StringToUTF16Ptr(want.Path), MaxUses: ^uint32(0), SD: sd}
	p := nativeNet.NewProc("NetShareAdd")
	if e = p.Find(); e != nil {
		return e
	}
	var field uint32
	rc64, _, _ := p.Call(0, 502, uintptr(unsafe.Pointer(&r)), uintptr(unsafe.Pointer(&field)))
	runtime.KeepAlive(r)
	runtime.KeepAlive(sd)
	if rc64 != 0 {
		return fmt.Errorf("NATIVE_SMB_CREATE_FAILED: %d field=%d", rc64, field)
	}
	got, free, rc, e = getNativeShare(want.Name)
	if e != nil {
		return e
	}
	if rc != 0 {
		return fmt.Errorf("NATIVE_SMB_READBACK_FAILED: %d", rc)
	}
	defer free()
	if !ownedNativeShare(want, got) {
		return fmt.Errorf("NATIVE_SMB_READBACK_CHANGED")
	}
	return nil
}
func ensureNativeSMB() error {
	// SMB2/3 is native Windows functionality; SMB1 is never installed/enabled.
	if e := nativeSMBComponents(); e != nil {
		return e
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService("LanmanServer")
	if e != nil {
		return fmt.Errorf("Windows SMB 元件不可用，請使用「檢查／修復元件」：%w", e)
	}
	defer s.Close()
	c, e := s.Config()
	if e != nil {
		return e
	}
	if c.StartType != mgr.StartAutomatic {
		c.StartType = mgr.StartAutomatic
		if e = s.UpdateConfig(c); e != nil {
			return e
		}
	}
	st, e := s.Query()
	if e != nil {
		return e
	}
	if st.State == svc.Stopped {
		if e = s.Start(); e != nil {
			return e
		}
	}
	end := time.Now().Add(15 * time.Second)
	for time.Now().Before(end) {
		st, e = s.Query()
		if e != nil {
			return e
		}
		if st.State == svc.Running {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("Windows SMB 服務尚未啟動")
}

// Configuration persists in Windows. Startup only observes it and never
// recreates a share removed through Windows. Only exact owned shares are deleted.
func SetNativeSMB(enabled bool) error {
	nativeSMBOperationMu.Lock()
	defer nativeSMBOperationMu.Unlock()
	return setNativeSMB(enabled)
}

func setNativeSMB(enabled bool) error {
	var cat *fileshare.Catalog
	if enabled {
		var err error
		cat, err = RefreshSharedFolders()
		if err != nil {
			return err
		}
	}
	nativeSMBMu.Lock()
	defer func() { nativeSMBMu.Unlock(); invalidateNativeSMB() }()
	c, e := loadNativeSMB()
	if e != nil {
		return e
	}
	if !enabled {
		attemptedRestore := map[string]bool{}
		e = retireSMBItems(c.Shares, deleteNativeShare, func(remaining []nativeSMBShare) error {
			next := c
			next.Shares = remaining
			if err := saveNativeSMB(next); err != nil {
				return err
			}
			c = next
			return nil
		}, func(s nativeSMBShare) error { attemptedRestore[s.ID] = true; return restoreSMBRoot(s.ID) })
		// ACL receipts remain independent of share receipts. Retry interrupted
		// cleanup on later clicks, while leaving externally modified shares alone.
		acls, er := loadSMBACLs()
		e = errors.Join(e, er)
		if er == nil {
			for _, r := range acls.Roots {
				retained := false
				for _, s := range c.Shares {
					retained = retained || s.ID == r.ID
				}
				if !retained && !attemptedRestore[r.ID] {
					e = errors.Join(e, restoreSMBRoot(r.ID))
				}
			}
		}
		return errors.Join(e, netconfig.Run(RemoveNativeSMBFirewallRules(), log.New(io.Discard, "", 0)))
	}
	if e = ensureNativeSMB(); e != nil {
		return e
	}
	if e = migrateNativeSMBVolumes(cat, &c); e != nil {
		return e
	}
	sid, e := nativeShareSID()
	if e != nil {
		return e
	}
	guest, e := nativeGuestSID()
	if e != nil {
		return e
	}
	var failures []error
	for _, s := range c.Shares {
		if s.GuestUpdate || s.GuestSID != guest {
			failures = append(failures, updateNativeGuestSharesLocked(&c, guest))
			break
		}
	}
	usedNames := map[string]string{}
	for _, s := range c.Shares {
		usedNames[s.Name] = s.ID
		if s.MigrationName != "" {
			usedNames[s.MigrationName] = s.ID
		}
	}
	for _, f := range cat.List() {
		if !f.Available {
			failures = append(failures, fmt.Errorf("共享資料夾不可用：%s；其他資料夾仍可共享", f.Name))
			continue
		}
		want := nativeSMBShare{ID: f.ID, Name: folderShareName(f.Path), Path: f.Path, SID: sid, GuestSID: guest}
		accessConflict := false
		hasAccessSetting := false
		for _, p := range c.Access {
			if p.ID == f.ID {
				if !strings.EqualFold(filepath.Clean(p.Path), filepath.Clean(f.Path)) || "win:"+p.FileID != f.Identity {
					failures = append(failures, fmt.Errorf("NATIVE_SMB_ACCESS_ROOT_CHANGED: %s", f.Name))
					accessConflict = true
					break
				}
				hasAccessSetting = true
				want.AccountAccess, want.GuestAccess = p.Account, p.Guest
			}
		}
		if accessConflict {
			continue
		}
		found, conflict := false, false
		for _, old := range c.Shares {
			if old.ID == f.ID {
				preserveSMBReceiptAccess(&want, old, hasAccessSetting)
				want.Name = old.Name
				want.NamePath = old.NamePath
				want.MigrationName, want.MigrationFileID = old.MigrationName, old.MigrationFileID
				if old.AccessUpdate {
					failures = append(failures, fmt.Errorf("NATIVE_SMB_ACCESS_RECOVERY_REQUIRED: %s", f.Name))
					conflict = true
				}
				if old.GuestUpdate || old != want {
					failures = append(failures, fmt.Errorf("NATIVE_SMB_RECEIPT_CHANGED: %s", f.Name))
					conflict = true
				}
				found = true
			}
		}
		if conflict {
			continue
		}
		if found && !fileshare.IsVolumePath(f.Path) && (want.MigrationName != "" || legacyNativeShareName(want.ID, want.Name) && !strings.EqualFold(want.Name, folderShareName(f.Path))) {
			oldName := want.Name
			want, e = migrateNativeSMBShare(&c, want, f, usedNames)
			if e != nil {
				return errors.Join(errors.Join(failures...), e)
			}
			delete(usedNames, oldName)
			usedNames[want.Name] = want.ID
		}
		if !found {
			if want.AccountAccess == "" {
				want.AccountAccess = "modify"
			}
			if want.GuestAccess == "" {
				want.GuestAccess = "none"
			}
			freeName := func(name string) (bool, error) {
				got, free, rc, err := getNativeShare(name)
				if err != nil {
					return false, err
				}
				if free != nil {
					defer free()
				}
				if rc == 2310 {
					return true, nil
				}
				if rc != 0 {
					return false, fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc)
				}
				candidate := want
				candidate.Name = name
				return ownedNativeShare(candidate, got), nil
			}
			bound := false
			for _, binding := range c.Names {
				if binding.ID != f.ID {
					continue
				}
				bound = true
				if !strings.EqualFold(binding.Path, f.Path) {
					e = fmt.Errorf("NATIVE_SMB_NAME_ROOT_CHANGED")
					break
				}
				want.Name, want.NamePath = binding.Name, binding.NamePath
				var free bool
				free, e = freeName(want.Name)
				for name, id := range usedNames {
					if id != f.ID && strings.EqualFold(name, want.Name) {
						free = false
					}
				}
				if e == nil && !free {
					e = fmt.Errorf("NATIVE_SMB_NAME_CONFLICT: %s", want.Name)
				}
				break
			}
			if !bound {
				want.Name, e = availableNativeShareName(f.ID, f.Path, usedNames, freeName)
			}

			if e != nil {
				failures = append(failures, e)
				continue
			}
			if len(c.Shares) >= 32 {
				failures = append(failures, fmt.Errorf("NATIVE_SMB_SHARE_LIMIT"))
				continue
			}
			c.Shares = append(c.Shares, want)
			rememberSMBShareName(&c, want)
			if e = saveNativeSMB(c); e != nil {
				return e
			}
			usedNames[want.Name] = want.ID
		}
		extra := []string{}
		if account, e := loadSMBAccount(); e == nil && account.SID == sid {
			extra = append(extra, sid)
		}
		if want.GuestSID != "" {
			extra = append(extra, want.GuestSID)
		}
		if e = grantSMBRoot(f.ID, f.Path, extra); e != nil {
			failures = append(failures, e)
			continue
		}
		if e = addNativeShare(want); e != nil {
			failures = append(failures, e)
		}
	}
	scopes, e := usbgateway.NativeSMBScopes()
	if e != nil {
		return errors.Join(errors.Join(failures...), e)
	}
	if len(scopes) != 0 {
		ruleScopes := make([]netconfig.NativeSMBServiceScope, 0, len(scopes))
		for _, scope := range scopes {
			ruleScopes = append(ruleScopes, netconfig.NativeSMBServiceScope{GUID: scope.GUID, Peer: scope.Peer})
		}
		script, e := netconfig.NativeSMBServicesRules(ruleScopes)
		if e != nil {
			return e
		}
		failures = append(failures, netconfig.Run(script, log.New(io.Discard, "", 0)))
	}

	return errors.Join(failures...)
}
func RemoveNativeSMBFolder(id string) error {
	nativeSMBOperationMu.Lock()
	defer nativeSMBOperationMu.Unlock()
	nativeSMBMu.Lock()
	defer func() { nativeSMBMu.Unlock(); invalidateNativeSMB() }()
	c, e := loadNativeSMB()
	if e != nil {
		return e
	}
	for i, s := range c.Shares {
		if s.ID == id {
			if e = deleteNativeShare(s); e != nil {
				return e
			}
			c.Shares = append(c.Shares[:i], c.Shares[i+1:]...)
			forgetSMBShareName(&c, id)
			for j := len(c.Access) - 1; j >= 0; j-- {
				if c.Access[j].ID == id {
					c.Access = append(c.Access[:j], c.Access[j+1:]...)
				}
			}
			if e = saveNativeSMB(c); e != nil {
				return e
			}
			return restoreSMBRoot(id)
		}
	}
	forgetSMBShareName(&c, id)
	if e = saveNativeSMB(c); e != nil {
		return e
	}
	return restoreSMBRoot(id)
}

// Only explicit local consent can discard an ACL recovery journal. This does
// not rewrite externally changed permissions, or silently leave Guest grants
// behind without explaining that they will be retained.
func ForgetNativeSMBACL(id string, confirmed bool) error {
	if !confirmed || !fileshare.ValidFolderID(id) {
		return fmt.Errorf("SMB_ACL_LOCAL_CONFIRMATION_REQUIRED")
	}
	nativeSMBOperationMu.Lock()
	defer nativeSMBOperationMu.Unlock()
	nativeSMBMu.Lock()
	defer func() { nativeSMBMu.Unlock(); invalidateNativeSMB() }()
	c, e := loadNativeSMB()
	if e != nil {
		return e
	}
	for _, s := range c.Shares {
		if s.ID == id {
			return fmt.Errorf("請先關閉此資料夾的共享，再保留目前權限。")
		}
	}
	// Also refuse if Windows still has this name, even if a previous receipt
	// write was lost or somebody modified the share externally.
	names := []string{nativeShareName(id), "USB-" + id, "USB-Link-" + id}
	acls, err := loadSMBACLs()
	if err != nil {
		return err
	}
	var rootPath, rootID string
	for _, root := range acls.Roots {
		if root.ID == id {
			rootPath, rootID = root.Path, root.FileID
			actual, e := smbRootFileIdentity(root.Path)
			if e != nil {
				return e
			}
			if !validSMBFileIdentity(rootID) || actual != rootID {
				return fmt.Errorf("SMB_ROOT_IDENTITY_CHANGED")
			}
			for i := 1; i <= 100; i++ {
				names = append(names, numberedShareName(folderShareName(root.Path), i))
			}
		}
	}
	for _, name := range names {
		got, free, rc, e := getNativeShare(name)
		unrelated := false
		if e == nil && rc == 0 && got != nil && got.Path != nil && rootPath != "" {
			path := windows.UTF16PtrToString(got.Path)
			if filepath.IsAbs(path) {
				fileID, identityError := smbRootFileIdentity(path)
				unrelated = identityError == nil && smbRecoveryShareUnrelated(rootPath, rootID, path, fileID)
			}
		}
		if free != nil {
			free()
		}
		if e != nil {
			return e
		}
		if rc != 2310 && !unrelated {
			return fmt.Errorf("SMB_ACL_SHARE_REMOVAL_UNCONFIRMED: %d", rc)
		}
	}
	return keepNativeSMBRootPermissions(id)
}

func keepNativeSMBRootPermissions(id string) error {
	acls, e := loadSMBACLs()
	if e != nil {
		return e
	}
	for i, r := range acls.Roots {
		if r.ID == id {
			if id == "000000000000000000000001" {
				// The protected default directory still needs a locally approved baseline
				// for startup ownership validation. This receipt performs no ACL restore.
				sd, fileID, e := smbRootSecurity(r.Path)
				if e != nil {
					return e
				}
				if r.FileID != "" && r.FileID != fileID {
					return fmt.Errorf("SMB_ROOT_IDENTITY_CHANGED")
				}
				acls.Roots[i] = smbACLReceipt{ID: r.ID, Path: r.Path, Before: sd.String(), After: sd.String(), FileID: fileID, AcceptedBaseline: true, Retained: true}
			} else {
				acls.Roots = append(acls.Roots[:i], acls.Roots[i+1:]...)
			}
			p, e := smbACLPath()
			if e != nil {
				return e
			}
			return writeSMBACLs(p, acls)
		}
	}
	return nil
}
func invalidateNativeSMB() {
	nativeSMBCache.Lock()
	nativeSMBCache.At = time.Time{}
	nativeSMBCache.Unlock()
}
func NativeSMBStatus() NativeSMBInfo {
	nativeSMBCache.Lock()
	if time.Since(nativeSMBCache.At) < 2*time.Second {
		info := nativeSMBCache.Info
		nativeSMBCache.Unlock()
		fileshare.USB.Enabled.Store(info.Enabled)
		return info
	}
	last := nativeSMBCache.Info
	nativeSMBCache.Unlock()
	if !nativeSMBMu.TryLock() {
		last.Busy = true
		last.Problem = "正在更新共享設定…"
		fileshare.USB.Enabled.Store(last.Enabled)
		return last
	}
	defer nativeSMBMu.Unlock()
	info := NativeSMBInfo{ConnectURL: nativeSMBConnectURL(nil)}
	account := NativeSMBAccountView(false)
	info.Username, info.Problem = account.Username, account.Problem
	m, e := mgr.Connect()
	if e == nil {
		if s, er := m.OpenService("LanmanServer"); er == nil {
			st, er := s.Query()
			info.Ready = er == nil && st.State == svc.Running
			s.Close()
		}
		m.Disconnect()
	}
	if er := nativeSMBComponents(); er != nil {
		info.Ready = false
		info.Problem = er.Error()
	}
	c, e := loadNativeSMB()
	var sharedNames []string
	if e == nil {
		for _, s := range c.Shares {
			if s.MigrationName != "" {
				name, err := observeNativeSMBMigration(s)
				if name != "" {
					info.Shared++
					sharedNames = append(sharedNames, name)
				}
				info.Problem = "共享名稱更新待完成；請重試共享或取消共享。"
				if err != nil {
					info.Problem += " " + err.Error()
				}
				continue
			}
			got, free, rc, er := getNativeShare(s.Name)
			if er == nil && rc == 0 {
				if ownedNativeShare(s, got) {
					info.Shared++
					sharedNames = append(sharedNames, s.Name)
				} else {
					info.Problem = "共享已在 Windows 修改；程式不會覆寫。"
				}
				free()
			} else if er != nil {
				info.Problem = er.Error()
			} else {
				info.Problem = fmt.Sprintf("Windows 共享 %s 無法讀取（%d）；請重試共享設定。", s.Name, rc)
			}
		}
	} else {
		info.Problem = e.Error()
	}
	if acls, er := loadSMBACLs(); er != nil {
		info.Problem = er.Error()
	} else {
		for _, r := range acls.Roots {
			retained := false
			for _, s := range c.Shares {
				retained = retained || s.ID == r.ID
			}
			if !retained && !r.Retained {
				info.Problem = "共享已關閉；部分資料夾權限待恢復。請在共享資料夾面板重試或保留目前權限。"
				break
			}
		}
	}
	info.Enabled = info.Shared > 0
	info.ConnectURL = nativeSMBConnectURL(sharedNames)
	if !info.Ready && info.Problem == "" {
		info.Problem = "Windows SMB 服務不可用或已停止"
	}
	nativeSMBCache.Lock()
	nativeSMBCache.At = time.Now()
	nativeSMBCache.Info = info
	nativeSMBCache.Unlock()
	fileshare.USB.Enabled.Store(info.Enabled)
	return info
}
func NativeSMBFolders(rows []fileshare.Folder) []fileshare.Folder {
	nativeSMBMu.Lock()
	defer nativeSMBMu.Unlock()
	c, e := loadNativeSMB()
	if e != nil {
		return rows
	}
	for _, s := range c.Shares {
		found := false
		for _, r := range rows {
			found = found || r.ID == s.ID
		}
		if !found {
			rows = append(rows, fileshare.Folder{ID: s.ID, Name: filepath.Base(s.Path), Path: s.Path, Problem: "Windows 共享記錄仍在；此資料夾不在目前選擇列表", SMBURL: nativeFolderSMBURL(s.Name)})
		}
	}
	for i := range rows {
		rows[i].DisplayPath = fileshare.DisplayVolumePath(rows[i].Path)
		rows[i].ShareName = folderShareName(rows[i].Path)
		for _, b := range c.Names {
			if b.ID == rows[i].ID {
				rows[i].ShareName = b.Name
			}
		}
		rows[i].SMBURL = nativeFolderSMBURL(rows[i].ShareName)
		for _, s := range c.Shares {
			if s.ID == rows[i].ID {
				rows[i].ShareName = s.Name
				rows[i].AccountAccess = displayedSMBAccess(s.AccountAccess, true)
				rows[i].GuestAccess = displayedSMBAccess(s.GuestAccess, s.GuestSID != "")
				rows[i].GuestEnabled = s.GuestSID != ""
				if s.GuestAccess != "" {
					rows[i].GuestAccess = s.GuestAccess
				}
				rows[i].AccessRecovery = s.AccessUpdate
				rows[i].SMBURL = nativeFolderSMBURL(s.Name)
				got, free, rc, er := getNativeShare(s.Name)
				if er == nil && rc == 0 {
					rows[i].NativeShared = ownedNativeShare(s, got)
					if s.AccessUpdate {
						next := s
						next.AccountAccess, next.GuestAccess = s.NextAccountAccess, s.NextGuestAccess
						if sd, e := nativeShareSD(next); e == nil && sameNativeSMBShareACL(got.SD, sd) {
							rows[i].AccountAccess = displayedSMBAccess(next.AccountAccess, true)
							rows[i].GuestAccess = displayedSMBAccess(next.GuestAccess, next.GuestSID != "")
							if next.GuestAccess != "" {
								rows[i].GuestAccess = next.GuestAccess
							}
						}
					}
					rows[i].ManagedConflict = !rows[i].NativeShared
					free()
				} else if rc == 2310 && rows[i].Problem == "" {
					rows[i].Problem = "尚未成功發布到 Windows，裝置目前看不到此共享。請重試共享。"
				}
				if s.MigrationName != "" {
					rows[i].Problem = "共享名稱更新待完成；請重試共享或取消共享。"
					rows[i].MigrationPending = true
					target := s
					target.Name = s.MigrationName
					next, nextFree, nextRC, nextError := getNativeShare(target.Name)
					if nextError == nil && nextRC == 0 {
						owned := ownedNativeShare(target, next)
						rows[i].ManagedConflict = rows[i].ManagedConflict || !owned
						if owned && !rows[i].NativeShared {
							rows[i].NativeShared = true
							rows[i].ShareName = target.Name
							rows[i].SMBURL = nativeFolderSMBURL(target.Name)
						}
					}
					if nextFree != nil {
						nextFree()
					}
				}
			}
		}
	}
	if acls, e := loadSMBACLs(); e == nil {
		for _, r := range acls.Roots {
			recoveryNeeded := true
			if r.Retained {
				sd, fileID, err := smbRootSecurity(r.Path)
				recoveryNeeded = err != nil || r.FileID != fileID || !sameSMBRootDACL(sd.String(), r.After)
			}

			found := false
			for i := range rows {
				if r.ID == rows[i].ID {
					found = true
					if !rows[i].NativeShared && recoveryNeeded {
						rows[i].PermissionRecovery = true
					}
				}
			}
			if !found {
				rows = append(rows, fileshare.Folder{ID: r.ID, Name: filepath.Base(r.Path), Path: r.Path, PermissionRecovery: recoveryNeeded, SMBURL: nativeFolderSMBURL(folderShareName(r.Path))})
			}
		}
	}

	return rows
}
func RepairNativeSMB(ctx context.Context) error {
	if NativeSMBStatus().Ready {
		return nil
	}
	system, e := windows.GetSystemDirectory()
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	// A stopped/disabled service needs configuration, not a system repair scan.
	if nativeSMBComponents() == nil {
		if e = ensureNativeSMB(); e == nil {
			invalidateNativeSMB()
			return nil
		}
	}
	k, er := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, registry.QUERY_VALUE)
	if er == nil {
		v, _, er := k.GetIntegerValue("SMB2")
		k.Close()
		if er == nil && v == 0 {
			c := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop';Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force -ErrorAction Stop;if(-not (Get-SmbServerConfiguration).EnableSMB2Protocol){throw 'SMB2 readback failed'}`)
			c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
			if e = c.Run(); e != nil {
				return fmt.Errorf("Windows SMB2/3 啟用未完成：%w", e)
			}
			invalidateNativeSMB()
			return ensureNativeSMB()
		}
	}
	// Official Windows servicing obtains components from the configured Windows
	// repair source. Missing system binaries are not downloaded from third parties.
	for _, job := range []struct {
		Name string
		Args []string
	}{{"Dism.exe", []string{"/Online", "/Cleanup-Image", "/RestoreHealth", "/NoRestart"}}, {"sfc.exe", []string{"/scannow"}}} {
		c := exec.CommandContext(ctx, filepath.Join(system, job.Name), job.Args...)
		c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
		if e = c.Run(); e != nil {
			return fmt.Errorf("Windows 官方修復未完成（%s）：%w；精簡系統可能需要相同版本的原版 Windows 修復來源", job.Name, e)
		}
	}
	invalidateNativeSMB()
	return ensureNativeSMB()
}

func nativeSMBComponents() error {
	for _, name := range []string{"NetShareGetInfo", "NetShareAdd", "NetShareDel", "NetShareSetInfo", "NetApiBufferFree"} {
		if e := nativeNet.NewProc(name).Find(); e != nil {
			return fmt.Errorf("Windows SMB 元件缺失，請使用「檢查／修復元件」：%w", e)
		}
	}
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, registry.QUERY_VALUE)
	if e != nil {
		return fmt.Errorf("Windows SMB 設定不可用，請使用「檢查／修復元件」：%w", e)
	}
	defer k.Close()
	v, _, e := k.GetIntegerValue("SMB2")
	if e != nil && e != registry.ErrNotExist {
		return e
	}
	if e == nil && v == 0 {
		return fmt.Errorf("Windows SMB2/3 已停用，請在 Windows 啟用後重試；不會啟用 SMB1。")
	}
	return nil
}

func RemoveNativeSMBFirewallRules() string {
	return `$ErrorActionPreference='Stop';$r=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop|Where-Object {$_.Name -like 'USB-Link-Native-SMB-*'});foreach($x in $r){if($x.Group -ne 'USB-Link-Owned-Services-v1' -or $x.Description -ne 'USB Link verified core service / v1'){throw 'SMB firewall ownership changed'};$x|Remove-NetFirewallRule -ErrorAction Stop};`
}

func readNativeSMBState(path string, v any) error {
	if e := noReparse(path); e != nil {
		return e
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil {
		return e
	}
	if len(b) > 1<<20 {
		return fmt.Errorf("NATIVE_SMB_STATE_TOO_LARGE")
	}
	return json.Unmarshal(b, v)
}

func NativeSMBDiagnostics() any {
	v := NativeSMBStatus()
	return map[string]any{"provider": "Windows native SMB", "ready": v.Ready, "enabled": v.Enabled, "server_url": NativeSMBServerURL, "connect_url": v.ConnectURL, "owned_share_count": v.Shared, "guest_enabled": NativeSMBGuestEnabled(), "dedicated_account_exists": NativeSMBAccountView(false).Exists, "account_read": nativeSMBAccountReadDiagnostics(), "folder_permission_writes": nativeSMBACLWriteDiagnostics(), "ui_results": nativeSMBUIResultDiagnostics(), "problem": v.Problem, "folders": NativeSMBFolderDiagnostics(), "policy": nativeSMBPolicyDiagnostics(), "readiness_scope": "service and owned shares only; remote authentication, share enumeration and file access require client verification"}
}

// Explicit local consent hands an externally modified share back to Windows.
// Never delete the share, change its descriptor, or undo retained permissions.
func ReleaseNativeSMBOwnership(id string, confirmed bool) error {
	if !confirmed || !fileshare.ValidFolderID(id) {
		return fmt.Errorf("SMB_RELEASE_LOCAL_CONFIRMATION_REQUIRED")
	}
	nativeSMBOperationMu.Lock()
	defer nativeSMBOperationMu.Unlock()
	nativeSMBMu.Lock()
	defer nativeSMBMu.Unlock()
	defer invalidateNativeSMB()
	c, e := loadNativeSMB()
	if e != nil {
		return e
	}
	for i, s := range c.Shares {
		if s.ID != id {
			continue
		}
		if s.MigrationName != "" {
			return fmt.Errorf("NATIVE_SMB_MIGRATION_RECOVERY_REQUIRED")
		}
		got, free, rc, err := getNativeShare(s.Name)
		if err != nil {
			return err
		}
		if free != nil {
			defer free()
		}
		if rc != 0 && rc != 2310 {
			return fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc)
		}
		if rc == 0 && ownedNativeShare(s, got) {
			return fmt.Errorf("共享仍由程式管理；請使用正常移除。")
		}
		return handoffSMBItem(func() error {
			// Revoke our selected membership before dropping either recovery
			// record. Interruption must not cause startup to republish this path.
			e := RemoveSharedFolder(id)
			if os.IsNotExist(e) {
				return nil
			}
			return e
		}, func() error {
			if e := keepNativeSMBRootPermissions(id); e != nil {
				return fmt.Errorf("資料夾已移出選擇列表；權限記錄待本機確認，可重試交由 Windows 管理：%w", e)
			}
			return nil
		}, func() error {
			c.Shares = append(c.Shares[:i], c.Shares[i+1:]...)
			forgetSMBShareName(&c, id)
			return saveNativeSMB(c)
		})
	}
	return fmt.Errorf("NATIVE_SMB_RECEIPT_NOT_FOUND")
}
