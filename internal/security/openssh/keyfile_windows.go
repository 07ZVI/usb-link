//go:build windows && amd64

package openssh

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Keep directory handles open without delete sharing throughout the operation.
// Reject junctions, symlinks and hard-linked files before reading/changing ACLs.
func withKeyFile(s Status, write bool, work func([]byte, func([]byte) error) error) error {
	path := filepath.Clean(s.Path)
	volume := filepath.VolumeName(path)
	if volume == "" || strings.HasPrefix(path, `\\`) {
		return fmt.Errorf("公鑰必須位於本機磁碟。")
	}
	var locks []windows.Handle
	defer func() {
		for i := len(locks) - 1; i >= 0; i-- {
			windows.CloseHandle(locks[i])
		}
	}()
	parent := filepath.Dir(path)
	current := volume + `\`
	for _, part := range append([]string{""}, strings.Split(strings.TrimPrefix(parent, current), `\`)...) {
		if part != "" {
			current = filepath.Join(current, part)
		}
		p, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			if !write {
				return work(nil, nil)
			}
			// Only the final .ssh/ssh directory may be created, not a profile.
			if current != parent {
				return fmt.Errorf("使用者資料夾不存在，請先登入 Windows 一次。")
			}
			if err = os.Mkdir(current, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			h, err = windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		}
		if err != nil {
			return err
		}
		locks = append(locks, h)
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return fmt.Errorf("公鑰路徑含連結或無法核對的資料夾，已停止操作。")
		}
	}
	owner := "BA"
	extra := ""
	if !s.Shared {
		extra = "(A;;FA;;;" + s.SID + ")"
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + owner + "G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)" + extra)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	access := uint32(windows.GENERIC_READ)
	share := uint32(windows.FILE_SHARE_READ)
	creation := uint32(windows.OPEN_EXISTING)
	if write {
		access |= windows.GENERIC_WRITE | windows.WRITE_DAC | windows.WRITE_OWNER
		share = 0
		creation = windows.OPEN_ALWAYS
	}
	h, err := windows.CreateFile(p, access, share, &sa, creation, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if !write && (errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)) {
		return work(nil, nil)
	}
	if err != nil {
		return fmt.Errorf("無法開啟公鑰檔案（可能正由其他程式使用）：%w", err)
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return fmt.Errorf("公鑰檔案是連結或不是一般檔案，已停止操作。")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxKeyFile+1))
	if err != nil {
		return err
	}
	if len(data) > MaxKeyFile {
		return fmt.Errorf("公鑰檔案過大。")
	}
	if !write {
		return work(data, nil)
	}
	save := func(out []byte) error {
		// Restrict the opened object itself, never an attacker-replaced path.
		dacl, _, e := sd.DACL()
		if e != nil {
			return e
		}
		sid, _, e := sd.Owner()
		if e != nil {
			return e
		}
		if e = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, sid, nil, dacl, nil); e != nil {
			return e
		}
		// Retain recovery bytes until write + durable flush + readback succeed.
		var nonce [12]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return e
		}
		backup := filepath.Join(parent, ".usb-link-authorized-keys-"+hex.EncodeToString(nonce[:])+".bak")
		bp, _ := windows.UTF16PtrFromString(backup)
		bh, e := windows.CreateFile(bp, windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if e != nil {
			return e
		}
		bf := os.NewFile(uintptr(bh), backup)
		_, e = bf.Write(data)
		if e == nil {
			e = bf.Sync()
		}
		ce := bf.Close()
		if e == nil {
			e = ce
		}
		if e != nil {
			return e
		}
		writeBytes := func(b []byte) error {
			if _, e := f.Seek(0, 0); e != nil {
				return e
			}
			if _, e := f.Write(b); e != nil {
				return e
			}
			if e := f.Truncate(int64(len(b))); e != nil {
				return e
			}
			return f.Sync()
		}
		if e = writeBytes(out); e == nil {
			_, e = f.Seek(0, 0)
			if e == nil {
				var actual []byte
				actual, e = io.ReadAll(io.LimitReader(f, MaxKeyFile+1))
				if e == nil && string(actual) != string(out) {
					e = fmt.Errorf("公鑰寫入後核對失敗。")
				}
			}
		}
		if e != nil {
			_ = writeBytes(data)
			return fmt.Errorf("公鑰儲存失敗，原檔備份保留在 %s：%w", backup, e)
		}
		_ = os.Remove(backup)
		return nil
	}
	return work(data, save)
}
