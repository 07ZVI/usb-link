//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/transport/ipadsession"
	"sync"
	"time"
	"unsafe"
)

const trustRevokeDirectory = "USB Link Trust Recycle"
const trustRevokeFileSDDL = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
const trustRevokeDirSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

var trustRevokeMu sync.Mutex

// Fixed local IPC only. Even an authenticated caller cannot skip the native
// confirmation. The caller must not register an unattended remote mutation.
func ConfirmAndRevokeCurrentComputerTrust() (TrustRevokeResult, error) {
	trustRevokeMu.Lock()
	defer trustRevokeMu.Unlock()
	ctx, cancel := context.WithTimeout(connectionContext(), 5*time.Minute)
	defer cancel()
	before, binding, e := trustRevokeCurrentTarget(ctx)
	if e != nil {
		return trustRevokeFailure(e)
	}
	manual := trustRevokeOldManualTarget(binding.serial)
	yes, checks := NativePanelWithContext(ctx, "撤銷這台電腦保存的 iPad 信任", "只把這台 Windows 保存的目前 iPad 配對檔案移到受保護回收備份，不讀取檔案內容。\r\n\r\n不更改 iPad 或其他 Mac 的信任資料庫，不刪除其他設備的記錄，也不保證 Apple 已有的會話立即終止。完成後請重新插拔 iPad，若詢問信任請選「不信任」。\r\n\r\n回收備份會保留。下方選項只針對以前手動放在桌面 Lockdown 資料夾的指定備份；預設不刪除，勾選後仍會再次確認。", "移到回收備份", []PanelCheck{{Text: "另外刪除以前手動存放的這台 iPad 備份（再次確認）", Disabled: !manual}})
	if !yes || ctx.Err() != nil {
		return TrustRevokeResult{Code: "CANCELLED", Notice: "已取消，配對檔案與備份均保留。"}, nil
	}
	if e = trustRevokeFreshTarget(ctx, binding); e != nil {
		return trustRevokeFailure(e)
	}
	result, e := trustRevokeSavedRecord(ctx, before, binding)
	if e != nil {
		result.Code = "REFUSED"
		result.Notice = "未完成操作，原配對檔案未被移走；如果已產生操作記錄，會保留供檢查。"
		if result.RecordRelocated {
			result.Code = "BACKUP_REVIEW_REQUIRED"
			result.Notice = "配對檔案已移至回收位置，但尚未完成全部安全核對；已保留檔案及操作記錄，請勿自動覆蓋原位置。"
		}
		return result, e
	}
	if manual && len(checks) == 1 && checks[0] {
		deleted, de := confirmTrustRevokeOldManualBackup(ctx, binding)
		result.OldManualBackupDeleted = deleted
		if de != nil {
			result.Notice += " 舊手動備份尚未刪除。"
			return result, de
		}
	}
	return result, nil
}

// Optional fixed local action; not an arbitrary-file deletion API.
func ConfirmDeleteOldCurrentTrustBackup() (TrustRevokeResult, error) {
	trustRevokeMu.Lock()
	defer trustRevokeMu.Unlock()
	ctx, cancel := context.WithTimeout(connectionContext(), 5*time.Minute)
	defer cancel()
	_, binding, e := trustRevokeCurrentTarget(ctx)
	if e != nil {
		return trustRevokeFailure(e)
	}
	deleted, e := confirmTrustRevokeOldManualBackup(ctx, binding)
	if e != nil {
		return trustRevokeFailure(e)
	}
	r := TrustRevokeResult{Code: "OLD_BACKUP_RETAINED", OldManualBackupDeleted: deleted, Notice: "舊手動備份保留；回收備份不受影響。"}
	if deleted {
		r.Code = "OLD_BACKUP_DELETED"
		r.Notice = "已刪除明確確認的舊手動備份；回收備份保留。"
	}
	return r, nil
}

func trustRevokeFailure(e error) (TrustRevokeResult, error) {
	return TrustRevokeResult{Code: "REFUSED", Notice: "未能核對目前已記住的 iPad 或檔案安全條件；請先接入並確認記住設備。"}, e
}
func trustRevokeCurrentTarget(ctx context.Context) (Snapshot, usbDescriptorAttachment, error) {
	s := Inspect()
	b := descriptorAttachment(s)
	if ctx.Err() != nil || s.Error != "" || len(s.Devices) != 1 || !b.verified || !usbDescriptorRootMatches(b.root, b.serial) || len(trustRevokeLeaves(b.serial)) == 0 {
		return s, b, fmt.Errorf("TRUST_CURRENT_USB_DESCRIPTOR_UNPROVEN")
	}
	g := ipadsession.USBDescriptorGrant(b.serial, b.product, "12AB", "photo-mux-cfg3-to-ncm-union-cfg5-v3")
	if !g.Valid() || !connectionPreferences().TrustedUSB(g) {
		return s, b, fmt.Errorf("TRUST_FIRST_USB_CONFIRMATION_NOT_REMEMBERED")
	}
	if e := trustRevokeFreshTarget(ctx, b); e != nil {
		return s, b, e
	}
	return s, b, nil
}
func trustRevokeFreshTarget(ctx context.Context, b usbDescriptorAttachment) error {
	if ctx.Err() != nil || !b.same(descriptorAttachment(Inspect())) {
		return fmt.Errorf("TRUST_USB_IDENTITY_OR_ATTACHMENT_CHANGED")
	}
	g := ipadsession.USBDescriptorGrant(b.serial, b.product, "12AB", "photo-mux-cfg3-to-ncm-union-cfg5-v3")
	if !connectionPreferences().TrustedUSB(g) {
		return fmt.Errorf("TRUST_SAVED_USB_CONFIRMATION_CHANGED")
	}
	return nil
}

// Directory handles omit FILE_SHARE_DELETE to pin all ancestors while the
// operation runs. Neither a junction nor an ancestor rename can redirect it.
type trustRevokePinnedDirs []windows.Handle

func (p trustRevokePinnedDirs) close() {
	for i := len(p) - 1; i >= 0; i-- {
		windows.CloseHandle(p[i])
	}
}
func trustRevokeOpenDirectory(path string) (windows.Handle, error) {
	ptr, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return 0, e
	}
	h, e := windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if e != nil {
		return 0, e
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(h)
		return 0, fmt.Errorf("TRUST_DIRECTORY_NOT_REAL")
	}
	return h, nil
}
func trustRevokePinPath(path string) (trustRevokePinnedDirs, error) {
	path = filepath.Clean(path)
	vol := filepath.VolumeName(path)
	if len(vol) != 2 || vol[1] != ':' || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("TRUST_LOCAL_DRIVE_PATH_UNPROVEN")
	}
	current := vol + string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(path, current), string(filepath.Separator))
	paths := []string{current}
	for _, p := range parts {
		if p != "" {
			current = filepath.Join(current, p)
			paths = append(paths, current)
		}
	}
	var pinned trustRevokePinnedDirs
	for _, p := range paths {
		h, e := trustRevokeOpenDirectory(p)
		if e != nil {
			pinned.close()
			return nil, e
		}
		pinned = append(pinned, h)
	}
	return pinned, nil
}
func trustRevokeProgramData() (string, error) {
	base, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil || !strings.EqualFold(filepath.Clean(base), `C:\ProgramData`) {
		return "", fmt.Errorf("TRUST_FIXED_PROGRAM_DATA_UNPROVEN")
	}
	return base, nil
}
func trustRevokeSafeError(code string, e error) error {
	var n windows.Errno
	if errors.As(e, &n) {
		return fmt.Errorf("%s_WIN32_%d", code, uint32(n))
	}
	return fmt.Errorf("%s", code)
}

func trustRevokeSource(base string, leaves []string) (string, trustRevokePinnedDirs, error) {
	pinned, e := trustRevokePinPath(base)
	if e != nil {
		return "", nil, e
	}
	dir := base
	for _, part := range []string{"Apple", "Lockdown"} {
		dir = filepath.Join(dir, part)
		h, er := trustRevokeOpenDirectory(dir)
		if errors.Is(er, windows.ERROR_FILE_NOT_FOUND) {
			return "", pinned, nil
		}
		if er != nil {
			pinned.close()
			return "", nil, trustRevokeSafeError("TRUST_SOURCE_DIRECTORY_UNVERIFIED", er)
		}
		pinned = append(pinned, h)
	}
	source := ""
	for _, leaf := range leaves {
		path := filepath.Join(dir, leaf)
		a, er := trustRevokeAttributes(path)
		if errors.Is(er, windows.ERROR_FILE_NOT_FOUND) {
			continue
		}
		if er != nil {
			pinned.close()
			return "", nil, trustRevokeSafeError("TRUST_SOURCE_METADATA_UNREADABLE", er)
		}
		if er = trustRevokeFileShape(a.FileAttributes, 1, uint64(a.FileSizeHigh)<<32|uint64(a.FileSizeLow)); er != nil {
			pinned.close()
			return "", nil, er
		}
		if source != "" {
			pinned.close()
			return "", nil, fmt.Errorf("TRUST_SOURCE_RECORD_AMBIGUOUS")
		}
		source = path
	}
	return source, pinned, nil
}
func trustRevokeProtectedDirectory(base string) (string, trustRevokePinnedDirs, error) {
	dir := filepath.Join(base, trustRevokeDirectory)
	sd, e := windows.SecurityDescriptorFromString(trustRevokeDirSDDL)
	if e != nil {
		return "", nil, e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	ptr, _ := windows.UTF16PtrFromString(dir)
	if e = windows.CreateDirectory(ptr, &sa); e != nil && e != windows.ERROR_ALREADY_EXISTS {
		return "", nil, trustRevokeSafeError("TRUST_RECYCLE_DIRECTORY_CREATE_FAILED", e)
	}
	h, e := trustRevokeOpenDirectory(dir)
	if e != nil {
		return "", nil, e
	}
	actual, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if e != nil || !trustRevokeSecurityMatches(actual, sd) {
		windows.CloseHandle(h)
		return "", nil, fmt.Errorf("TRUST_RECYCLE_DIRECTORY_ACL_UNPROVEN")
	}
	return dir, trustRevokePinnedDirs{h}, nil
}
func trustRevokeOpenRecord(path string) (windows.Handle, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	ptr, _ := windows.UTF16PtrFromString(path)
	// No content-read access. Deny other writers/renamers and request WRITE_DAC
	// only to protect this same file after it has entered the recycle directory.
	h, e := windows.CreateFile(ptr, windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return 0, info, trustRevokeSafeError("TRUST_RECORD_BUSY_OR_UNREADABLE", e)
	}
	if e = windows.GetFileInformationByHandle(h, &info); e == nil {
		e = trustRevokeFileShape(info.FileAttributes, info.NumberOfLinks, uint64(info.FileSizeHigh)<<32|uint64(info.FileSizeLow))
	}
	if e != nil {
		windows.CloseHandle(h)
		return 0, info, trustRevokeSafeError("TRUST_RECORD_HANDLE_UNVERIFIED", e)
	}
	return h, info, nil
}
func trustRevokeProtectFile(h windows.Handle) error {
	sd, e := windows.SecurityDescriptorFromString(trustRevokeFileSDDL)
	if e != nil {
		return e
	}
	dacl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil {
		return fmt.Errorf("TRUST_BACKUP_OWNER_UNPROVEN")
	}
	if e = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION, owner, nil, dacl, nil); e != nil {
		return trustRevokeSafeError("TRUST_BACKUP_ACL_SET_FAILED", e)
	}
	actual, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if e != nil || !trustRevokeSecurityMatches(actual, sd) {
		return fmt.Errorf("TRUST_BACKUP_ACL_READBACK_FAILED")
	}
	return nil
}

// Absolute same-volume, no-replace rename of the already verified source handle.
// FileRenameInfo layout on Windows amd64: BOOLEAN+padding, HANDLE, DWORD, WCHAR[].
func trustRevokeRenameHandle(h windows.Handle, target string) error {
	name, e := windows.UTF16FromString(target)
	if e != nil {
		return e
	}
	name = name[:len(name)-1]
	b := make([]byte, 20+len(name)*2)
	binary.LittleEndian.PutUint32(b[16:20], uint32(len(name)*2))
	for i, v := range name {
		binary.LittleEndian.PutUint16(b[20+i*2:], v)
	}
	if e = windows.SetFileInformationByHandle(h, windows.FileRenameInfo, &b[0], uint32(len(b))); e != nil {
		return trustRevokeSafeError("TRUST_HANDLE_MOVE_FAILED", e)
	}
	return nil
}

type trustRevokeMetadata struct {
	Version          int              `json:"version"`
	Stage            string           `json:"stage"`
	DescriptorSHA256 string           `json:"usb_descriptor_sha256"`
	OriginalLeaf     string           `json:"original_leaf"`
	BackupLeaf       string           `json:"backup_leaf"`
	Volume           uint32           `json:"volume"`
	FileHigh         uint32           `json:"file_id_high"`
	FileLow          uint32           `json:"file_id_low"`
	Size             uint64           `json:"size"`
	Created          windows.Filetime `json:"created"`
	Written          windows.Filetime `json:"written"`
}

func trustRevokeWriteMetadata(path string, m trustRevokeMetadata) error {
	b, e := json.Marshal(m)
	if e != nil || len(b) > 2048 {
		return fmt.Errorf("TRUST_METADATA_INVALID")
	}
	sd, e := windows.SecurityDescriptorFromString(trustRevokeFileSDDL)
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	ptr, _ := windows.UTF16PtrFromString(path)
	h, e := windows.CreateFile(ptr, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if e != nil {
		return trustRevokeSafeError("TRUST_METADATA_CREATE_FAILED", e)
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return fmt.Errorf("TRUST_METADATA_HANDLE_FAILED")
	}
	defer f.Close()
	actual, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if e != nil || !trustRevokeSecurityMatches(actual, sd) {
		return fmt.Errorf("TRUST_METADATA_ACL_UNPROVEN")
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	if e != nil {
		return trustRevokeSafeError("TRUST_METADATA_DURABLE_WRITE_FAILED", e)
	}
	if _, e = f.Seek(0, 0); e != nil {
		return e
	}
	got, e := io.ReadAll(io.LimitReader(f, 2049))
	if e != nil || !bytes.Equal(got, b) {
		return fmt.Errorf("TRUST_METADATA_DURABLE_READBACK_FAILED")
	}
	return nil
}
func trustRevokeSameFile(a, b windows.ByHandleFileInformation) bool {
	return a.VolumeSerialNumber == b.VolumeSerialNumber && a.FileIndexHigh == b.FileIndexHigh && a.FileIndexLow == b.FileIndexLow && a.FileSizeHigh == b.FileSizeHigh && a.FileSizeLow == b.FileSizeLow && a.CreationTime == b.CreationTime && a.LastWriteTime == b.LastWriteTime && b.NumberOfLinks == 1 && b.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) == 0
}
func trustRevokeVerifyBackup(path string, original windows.ByHandleFileInformation) error {
	ptr, _ := windows.UTF16PtrFromString(path)
	h, e := windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return trustRevokeSafeError("TRUST_BACKUP_READBACK_FAILED", e)
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	e = windows.GetFileInformationByHandle(h, &info)
	sd, se := windows.SecurityDescriptorFromString(trustRevokeFileSDDL)
	actual, ae := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if e != nil || se != nil || ae != nil || !trustRevokeSameFile(original, info) || !trustRevokeSecurityMatches(actual, sd) {
		return fmt.Errorf("TRUST_BACKUP_IDENTITY_OR_ACL_CHANGED")
	}
	return nil
}
func trustRevokeSavedRecord(ctx context.Context, before Snapshot, binding usbDescriptorAttachment) (result TrustRevokeResult, err error) {
	base, e := trustRevokeProgramData()
	if e != nil {
		return result, e
	}
	source, parents, e := trustRevokeSource(base, trustRevokeLeaves(binding.serial))
	if e != nil {
		return result, e
	}
	defer parents.close()
	if source == "" {
		if e = trustRevokeFreshTarget(ctx, binding); e != nil {
			return result, e
		}
		return TrustRevokeResult{Code: "NO_LOCAL_RECORD", OriginalAbsenceVerified: true, ReconnectRequired: true, Notice: "本機目前沒有這台 iPad 的配對檔案，無需再移走。這不能判定 iPad 端的信任狀態；重新插拔後若詢問請點不信任。"}, nil
	}
	dir, pinned, e := trustRevokeProtectedDirectory(base)
	if e != nil {
		return result, e
	}
	defer pinned.close()
	h, original, e := trustRevokeOpenRecord(source)
	if e != nil {
		return result, e
	}
	closed := false
	defer func() {
		if !closed {
			windows.CloseHandle(h)
		}
	}()
	var di windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(pinned[0], &di) != nil || di.VolumeSerialNumber != original.VolumeSerialNumber {
		return result, fmt.Errorf("TRUST_BACKUP_NOT_SAME_LOCAL_VOLUME")
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return result, e
	}
	id := hex.EncodeToString(nonce[:])
	stage := filepath.Join(dir, id+".pending.plist")
	final := filepath.Join(dir, id+".plist")
	m := trustRevokeMetadata{1, "intent", before.Devices[0].USBSerialSHA256, filepath.Base(source), filepath.Base(final), original.VolumeSerialNumber, original.FileIndexHigh, original.FileIndexLow, uint64(original.FileSizeHigh)<<32 | uint64(original.FileSizeLow), original.CreationTime, original.LastWriteTime}
	err = runTrustRevokeTransaction(func() error {
		err := trustRevokeWriteMetadata(filepath.Join(dir, id+".intent.json"), m)
		if err == nil {
			result.OperationMetadataRetained = true
		}
		return err
	}, func() error { return trustRevokeFreshTarget(ctx, binding) }, func() error {
		err := trustRevokeRenameHandle(h, stage)
		if err == nil {
			result.RecordRelocated = true
		}
		return err
	}, func() error { return trustRevokeProtectFile(h) }, func() error {
		return trustRevokeCloseAndDurableMove(h, &closed, stage, final)
	}, func() error {
		if e := trustRevokeVerifyBackup(final, original); e != nil {
			return e
		}
		result.MovedToProtectedBackup = true
		result.BackupMetadataVerified = true
		for _, leaf := range trustRevokeLeaves(binding.serial) {
			_, e := trustRevokeAttributes(filepath.Join(base, "Apple", "Lockdown", leaf))
			if !errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
				return fmt.Errorf("TRUST_ORIGINAL_ABSENCE_NOT_VERIFIED")
			}
		}
		result.OriginalAbsenceVerified = true
		return trustRevokeFreshTarget(ctx, binding)
	}, func() error {
		m.Stage = "verified_complete"
		return trustRevokeWriteMetadata(filepath.Join(dir, id+".complete.json"), m)
	})
	result.ReconnectRequired = true
	if err != nil {
		return result, err
	}
	result.Code = "WINDOWS_RECORD_MOVED"
	result.Notice = "已把這台 Windows 的配對檔案移到受保護回收備份，備份保留。請重新插拔 iPad，詢問時點不信任；已有 Apple 會話與 iPad／Mac 的其他信任資料庫未被清除。"
	return result, nil
}

func confirmTrustRevokeOldManualBackup(ctx context.Context, binding usbDescriptorAttachment) (bool, error) {
	if !trustRevokeOldManualTarget(binding.serial) {
		return false, fmt.Errorf("TRUST_OLD_BACKUP_TARGET_NOT_EXACT")
	}
	desktop, e := connectioninstall.UserKnownFolderPath(windows.FOLDERID_Desktop, 0)
	if e != nil {
		return false, fmt.Errorf("TRUST_DESKTOP_UNAVAILABLE")
	}
	pins, e := trustRevokePinPath(desktop)
	if e != nil {
		return false, e
	}
	defer pins.close()
	dir := filepath.Join(desktop, "Lockdown")
	dh, e := trustRevokeOpenDirectory(dir)
	if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	defer windows.CloseHandle(dh)
	path := filepath.Join(dir, trustRevokeOldManualLeaf)
	_, e = trustRevokeAttributes(path)
	if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
		return false, nil
	}
	if e != nil {
		return false, trustRevokeSafeError("TRUST_OLD_BACKUP_METADATA_UNREADABLE", e)
	}
	h, _, e := trustRevokeOpenRecord(path)
	if e != nil {
		return false, e
	}
	defer func() {
		if h != 0 {
			windows.CloseHandle(h)
		}
	}()
	yes, _ := NativePanelWithContext(ctx, "刪除舊手動配對備份", "將永久刪除桌面 Lockdown 資料夾內以前手動備份的 00008103-0009716E3400201E.plist。\r\n\r\n這是不可復原的刪除，只影響這一個舊手動備份；USB Link 的受保護回收備份不會刪除。若不確定，請取消。", "確認刪除這個舊備份", nil)
	if !yes || ctx.Err() != nil {
		return false, nil
	}
	if e = trustRevokeFreshTarget(ctx, binding); e != nil {
		return false, e
	}
	// Delete this exact locked handle; no path-based delete can race substitution.
	b := []byte{1}
	if e = windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &b[0], uint32(len(b))); e != nil {
		return false, trustRevokeSafeError("TRUST_OLD_BACKUP_DELETE_FAILED", e)
	}
	closing := h
	h = 0
	if e = windows.CloseHandle(closing); e != nil {
		return false, trustRevokeSafeError("TRUST_OLD_BACKUP_HANDLE_CLOSE_FAILED", e)
	}
	_, e = trustRevokeAttributes(path)
	if !errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
		return false, fmt.Errorf("TRUST_OLD_BACKUP_DELETE_ABSENCE_UNVERIFIED")
	}
	return true, nil
}

func trustRevokeAttributes(path string) (windows.Win32FileAttributeData, error) {
	var data windows.Win32FileAttributeData
	ptr, e := windows.UTF16PtrFromString(path)
	if e == nil {
		e = windows.GetFileAttributesEx(ptr, 0, (*byte)(unsafe.Pointer(&data)))
	}
	return data, e
}
func trustRevokeSecurityMatches(actual, expected *windows.SECURITY_DESCRIPTOR) bool {
	if actual == nil || expected == nil || !groupingACLMatches(actual, expected) {
		return false
	}
	ao, _, ae := actual.Owner()
	eo, _, ee := expected.Owner()
	return ae == nil && ee == nil && ao != nil && eo != nil && ao.Equals(eo)
}

// After the source has entered the protected directory and its owner/DACL have
// been verified, close its mutation handle before the write-through final move.
func trustRevokeCloseAndDurableMove(h windows.Handle, closed *bool, stage, final string) error {
	*closed = true
	if e := windows.CloseHandle(h); e != nil {
		return trustRevokeSafeError("TRUST_SOURCE_HANDLE_CLOSE_FAILED", e)
	}
	from, _ := windows.UTF16PtrFromString(stage)
	to, _ := windows.UTF16PtrFromString(final)
	if e := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return trustRevokeSafeError("TRUST_DURABLE_BACKUP_MOVE_FAILED", e)
	}
	return nil
}
