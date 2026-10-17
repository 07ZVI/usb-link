//go:build windows && amd64

package ipadncm

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/sharing/fileshare"
	"sync"
)

var shareFoldersBusy sync.Mutex

func (u *modernUI) sendEvent(message any) {
	u.mu.Lock()
	messages, done, service := u.messages, u.childDone, u.serviceOwner
	u.mu.Unlock()
	if messages == nil {
		return
	}
	if service {
		if retainSMBUIResult(message) {
			return
		}
		select {
		case messages <- message:
		default:
		}
		return
	}
	select {
	case messages <- message:
	case <-u.lifetime.Done():
	case <-done:
	}
}
func (u *modernUI) shareFoldersAction(v desktopRequest) bool {
	if v.Action == "windows-smb-manage" {
		path, err := windows.GetSystemDirectory()
		if err == nil {
			err = windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(filepath.Join(path, "mmc.exe")), windows.StringToUTF16Ptr(filepath.Join(path, "fsmgmt.msc")), nil, 1)
		}
		if err != nil {
			u.setNotice("無法開啟 Windows 共享管理。")
		}
		return true
	}

	switch v.Action {
	case "share-folders-refresh", "share-folder-add", "share-folder-remove", "share-folder-open", "native-smb-access-save", "native-smb-acl-forget", "native-smb-release", "native-smb-account-read", "native-smb-account-save", "native-smb-account-create", "native-smb-account-reset", "native-smb-account-rename", "native-smb-guest-on", "native-smb-guest-off", "native-smb-repair", "native-smb-retry":
	default:
		return false
	}
	go func() {
		if v.Action == "native-smb-account-read" {
			u.sendEvent(map[string]any{"event": "smb-account", "action": v.Action, "request_id": v.ID, "account": connectioninstall.ReadNativeSMBAccount(v.Remember), "guest": connectioninstall.NativeSMBGuestEnabled()})
			return
		}
		shareFoldersBusy.Lock()
		defer shareFoldersBusy.Unlock()
		var err error
		var passwordSaved, nameSaved bool
		switch v.Action {
		case "share-folder-add":
			err = connectioninstall.AddSharedFolder(v.Path)
			if err == nil && v.AccountAccess != "" {
				err = connectioninstall.SetNewNativeSMBAccess(v.Path, v.AccountAccess, v.GuestAccess)
			}
			if err == nil {
				err = connectioninstall.SetNativeSMB(true)
			}
		case "share-folder-remove":
			err = connectioninstall.RemoveNativeSMBFolder(v.ID)
			if err == nil {
				err = connectioninstall.RemoveSharedFolder(v.ID)
				if os.IsNotExist(err) {
					err = nil
				}
			}

		case "native-smb-release":
			err = connectioninstall.ReleaseNativeSMBOwnership(v.ID, v.Remember)
			if err == nil {
				err = connectioninstall.RemoveSharedFolder(v.ID)
				if os.IsNotExist(err) {
					err = nil
				}
			}

		case "native-smb-acl-forget":
			err = connectioninstall.ForgetNativeSMBACL(v.ID, v.Remember)

		case "native-smb-account-create", "native-smb-account-reset":
			passwordSaved, err = connectioninstall.UpdateNativeSMBAccount(v.Action == "native-smb-account-reset", v.Password, v.Username)
		case "native-smb-account-save":
			nameSaved, passwordSaved, err = connectioninstall.SaveNativeSMBAccount(v.Username, v.Password)
		case "native-smb-access-save":
			err = connectioninstall.UpdateNativeSMBAccess(v.ID, v.AccountAccess, v.GuestAccess)
		case "native-smb-account-rename":
			err = connectioninstall.RenameSMBAccount(v.Username)
			nameSaved = err == nil
		case "native-smb-guest-on", "native-smb-guest-off":
			err = connectioninstall.SetNativeSMBGuestCompatible(v.Action == "native-smb-guest-on")
		case "native-smb-retry":
			err = connectioninstall.SetNativeSMB(true)
		case "native-smb-repair":
			u.setNotice("正在使用 Windows 官方元件修復；可能需要較長時間，請保持程式開啟。")
			err = connectioninstall.RepairNativeSMB(u.lifetime)
		}
		if strings.HasPrefix(v.Action, "native-smb-account-") {
			problem := ""
			if err != nil {
				problem = err.Error()
			}
			account := connectioninstall.NativeSMBAccountView(false)
			if passwordSaved || nameSaved {
				account = connectioninstall.ReadNativeSMBAccount(false)
			}
			u.sendEvent(map[string]any{"event": "smb-account", "action": v.Action, "request_id": v.ID, "account": account, "guest": connectioninstall.NativeSMBGuestEnabled(), "problem": problem, "name_saved": nameSaved, "password_saved": passwordSaved})
			return
		}
		c, e := connectioninstall.ShareCatalog()
		if err == nil {
			err = e
		}
		folders := []fileshare.Folder{}
		if c != nil {
			if v.Action == "share-folders-refresh" {
				_, e = connectioninstall.RefreshSharedFolders()
				if err == nil {
					err = e
				}
			}
			folders = c.List()
			if v.Action == "share-folder-open" {
				var path string
				path, e = c.Path(v.ID)
				if e == nil {
					e = windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(path), nil, nil, 1)
				}
				if err == nil {
					err = e
				}
			}
		}
		folders = connectioninstall.NativeSMBFolders(folders)
		problem := ""
		if err != nil {
			problem = err.Error()
		}
		if v.RequestID != "" {
			folders, e = connectioninstall.NativeSMBManagerFolders()
			if e != nil {
				problem = e.Error()
			}
		}
		u.sendEvent(map[string]any{"event": "share-folders", "action": v.Action, "request_id": v.RequestID, "folders": folders, "problem": problem})
		if v.RequestID == "" {
			// Maintenance-window actions use their independent account receipt.
			// Folder retries return only their correlated folder result.
			account := connectioninstall.NativeSMBAccountView(false)
			u.sendEvent(map[string]any{"event": "smb-account", "action": v.Action, "request_id": v.ID, "account": account, "guest": connectioninstall.NativeSMBGuestEnabled(), "problem": problem})
		}
	}()
	return true
}
