//go:build windows && amd64

package connectioninstall

import (
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"
)

func externalSMBSnapshot(got *nativeShare502) (string, error) {
	if got == nil || got.Name == nil || got.Path == nil || got.SD == nil || got.Type != 0 {
		return "", fmt.Errorf("SMB_EXTERNAL_SHARE_INVALID")
	}
	name := windows.UTF16PtrToString(got.Name)
	if name == "" || strings.HasSuffix(name, "$") {
		return "", fmt.Errorf("SMB_SYSTEM_SHARE_PROTECTED")
	}
	return externalSMBID(name, windows.UTF16PtrToString(got.Path), windows.UTF16PtrToString(got.Remark), got.SD.String()), nil
}

// Only an explicit confirmed action on a freshly read external share can change
// it. Filesystem ACLs and directory contents are never modified here.
func ChangeExternalSMBShare(id string, remove bool, account, guest string, confirmed bool) error {
	if !confirmed || !IsExternalSMBID(id) {
		return fmt.Errorf("SMB_EXTERNAL_CONFIRMATION_REQUIRED")
	}
	if !remove && (account == "" || guest == "" || !validSMBAccess(account) || !validSMBAccess(guest)) {
		return fmt.Errorf("NATIVE_SMB_ACCESS_INVALID")
	}
	nativeSMBOperationMu.Lock()
	defer nativeSMBOperationMu.Unlock()
	nativeSMBMu.Lock()
	defer func() { nativeSMBMu.Unlock(); invalidateNativeSMB() }()
	config, err := loadNativeSMB()
	if err != nil {
		return err
	}
	shares, err := enumerateNativeDiskShares()
	if err != nil {
		return err
	}
	for _, share := range shares {
		var managed *nativeSMBShare
		for _, s := range config.Shares {
			if strings.EqualFold(s.Name, share.Name) || s.MigrationName != "" && strings.EqualFold(s.MigrationName, share.Name) {
				copy := s
				managed = &copy
			}
		}
		if managed != nil && (!remove || managed.MigrationName != "") {
			continue
		}
		got, free, rc, e := getNativeShare(share.Name)
		if e != nil {
			return e
		}
		if rc != 0 {
			continue
		}
		fingerprint, e := externalSMBSnapshot(got)
		if e != nil || fingerprint != id {
			free()
			continue
		}
		if managed != nil && ownedNativeShare(*managed, got) {
			free()
			continue
		}
		before := got.SD.String()
		path := windows.UTF16PtrToString(got.Path)
		free()
		// Persist the exact before state before a Windows API mutation. Retain only
		// the latest operation per share name, capped at the native state reader size.
		var after *windows.SECURITY_DESCRIPTOR
		if !remove {
			sid, e := nativeShareSID()
			if e != nil {
				return e
			}
			guestSID, e := nativeGuestSID()
			if e != nil {
				return e
			}
			if guest != "none" && guestSID == "" {
				return fmt.Errorf("請先啟用全機訪客，再設定此共享的訪客權限。")
			}
			after, e = nativeShareSD(nativeSMBShare{SID: sid, GuestSID: guestSID, AccountAccess: account, GuestAccess: guest})
			if e != nil {
				return e
			}
		}
		directory, e := SecurityDirectory()
		if e != nil {
			return e
		}
		record := struct {
			Name, Path, Before, LastBefore, After string
			Remove                                bool
		}{share.Name, path, before, before, "", remove}
		if after != nil {
			record.After = after.String()
		}
		if len(record.Before)+len(record.After)+len(path) > 1<<19 {
			return fmt.Errorf("SMB_EXTERNAL_BACKUP_TOO_LARGE")
		}
		// Fixed filename bound to the server-derived share name, never client paths.
		backupName := externalSMBID(share.Name, "", "", "")[9:]
		backupPath := filepath.Join(directory, "external-smb-"+backupName+".json")
		previous := record
		if readErr := readNativeSMBState(backupPath, &previous); readErr == nil {
			if previous.Name == record.Name && previous.Path == record.Path {
				record.Before = previous.Before
			}
		} else if !os.IsNotExist(readErr) {
			return readErr
		}
		encoded, encodeErr := json.Marshal(record)
		if encodeErr != nil {
			return encodeErr
		}
		if len(encoded) > 1<<20 {
			return fmt.Errorf("SMB_EXTERNAL_BACKUP_TOO_LARGE")
		}
		if e = writeRemote(backupPath, record); e != nil {
			return e
		}
		if managed != nil {
			// The user confirmed the currently displayed Windows snapshot,
			// including external edits; revoke automated publication first.
			if err := RemoveSharedFolder(managed.ID); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		// Re-read after saving, so a changed target cannot be mistaken for approval.
		got, free, rc, e = getNativeShare(share.Name)
		if e != nil {
			return e
		}
		if rc != 0 {
			return fmt.Errorf("SMB_EXTERNAL_CHANGED_REFRESH_REQUIRED")
		}
		current, e := externalSMBSnapshot(got)
		free()
		if e != nil || current != id {
			return fmt.Errorf("SMB_EXTERNAL_CHANGED_REFRESH_REQUIRED")
		}
		var field uint32
		if remove {
			result, _, _ := nativeNet.NewProc("NetShareDel").Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(share.Name))), 0)
			if result != 0 && result != 2310 {
				return fmt.Errorf("NATIVE_SMB_REMOVE_FAILED: %d", result)
			}
		} else {
			info := struct{ SD *windows.SECURITY_DESCRIPTOR }{after}
			result, _, _ := nativeNet.NewProc("NetShareSetInfo").Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(share.Name))), 1501, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&field)))
			runtime.KeepAlive(after)
			if result != 0 {
				return fmt.Errorf("NATIVE_SMB_ACCESS_SAVE_FAILED: %d", result)
			}
		}
		got, free, rc, e = getNativeShare(share.Name)
		if e != nil {
			return e
		}
		if remove {
			if free != nil {
				free()
			}
			if rc != 2310 {
				return fmt.Errorf("NATIVE_SMB_REMOVE_READBACK_FAILED")
			}
			if managed != nil {
				forgetNativeSMBFolder(&config, managed.ID)
				if err := saveNativeSMB(config); err != nil {
					return err
				}
				if err := restoreSMBRoot(managed.ID); err != nil {
					return fmt.Errorf("共享已取消；資料夾權限恢復待完成：%w", err)
				}
			}
			return nil
		}
		if rc != 0 {
			return fmt.Errorf("NATIVE_SMB_READBACK_FAILED: %d", rc)
		}
		ok := strings.EqualFold(windows.UTF16PtrToString(got.Path), path) && sameNativeSMBShareACL(got.SD, after)
		free()
		if !ok {
			return fmt.Errorf("NATIVE_SMB_READBACK_CHANGED")
		}
		return nil
	}
	return fmt.Errorf("SMB_EXTERNAL_CHANGED_REFRESH_REQUIRED")
}
