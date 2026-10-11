//go:build windows && amd64

package ipadncm

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

type TrustRecycleNativeSelfTestResult struct {
	Code                      string `json:"code"`
	NoOverwriteVerified       bool   `json:"no_overwrite_verified"`
	FileIdentityVerified      bool   `json:"file_identity_verified"`
	ProtectedOwnerACLVerified bool   `json:"protected_owner_acl_verified"`
	OriginalAbsentVerified    bool   `json:"original_absent_verified"`
	DurableFinalMoveVerified  bool   `json:"durable_final_move_verified"`
	ReparseRefusalVerified    bool   `json:"reparse_refusal_verified"`
	CleanupComplete           bool   `json:"cleanup_complete"`
	Notice                    string `json:"notice"`
}

// Fixed authenticated diagnostic only. This creates its own synthetic metadata
// files under a protected random child; it never inspects Apple, Desktop,
// descriptors or pairing material. Success validates native file mechanics only.
func RunTrustRecycleNativeSelfTest() (result TrustRecycleNativeSelfTestResult, err error) {
	if !trustRevokeMu.TryLock() {
		return result, fmt.Errorf("TRUST_SELFTEST_BUSY")
	}
	defer trustRevokeMu.Unlock()
	result.Code = "FAILED"
	result.Notice = "只驗證自建測試檔案的 Windows 檔案接口，並非配對檔案遷移或 iPad 驗收。"
	base, e := trustRevokeProgramData()
	if e != nil {
		return result, e
	}
	ancestors, e := trustRevokePinPath(base)
	if e != nil {
		return result, trustRevokeSafeError("TRUST_SELFTEST_ANCESTORS_UNPROVEN", e)
	}
	defer ancestors.close()
	recycle, recyclePins, e := trustRevokeProtectedDirectory(base)
	if e != nil {
		return result, trustRevokeSafeError("TRUST_SELFTEST_DIRECTORY_UNPROVEN", e)
	}
	defer recyclePins.close()
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return result, fmt.Errorf("TRUST_SELFTEST_NONCE_FAILED")
	}
	dir := filepath.Join(recycle, "native-selftest-"+hex.EncodeToString(nonce[:]))
	sd, e := windows.SecurityDescriptorFromString(trustRevokeDirSDDL)
	if e != nil {
		return result, fmt.Errorf("TRUST_SELFTEST_SECURITY_INVALID")
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	ptr, _ := windows.UTF16PtrFromString(dir)
	if e = windows.CreateDirectory(ptr, &sa); e != nil {
		return result, trustRevokeSafeError("TRUST_SELFTEST_CREATE_FAILED", e)
	}
	var directoryHandle windows.Handle
	var recordHandle windows.Handle
	closed := true
	// Cleanup names are literal children generated here; no recursive traversal or
	// caller-provided paths are ever deleted. Unknown extra files retain the folder.
	defer func() {
		if !closed {
			closed = true
			windows.CloseHandle(recordHandle)
		}
		if directoryHandle != 0 {
			windows.CloseHandle(directoryHandle)
		}
		clean := true
		for _, leaf := range []string{"source.dummy", "occupied.dummy", "staged.dummy", "final.dummy", "reparse.dummy"} {
			if ce := os.Remove(filepath.Join(dir, leaf)); ce != nil && !errors.Is(ce, os.ErrNotExist) {
				clean = false
			}
		}
		if ce := os.Remove(dir); ce != nil {
			clean = false
		}
		result.CleanupComplete = clean
		if !clean {
			result.Code = "CLEANUP_REQUIRED"
			if err == nil {
				err = fmt.Errorf("TRUST_SELFTEST_CLEANUP_INCOMPLETE")
			}
		}
	}()
	directoryHandle, e = trustRevokeOpenDirectory(dir)
	if e != nil {
		return result, trustRevokeSafeError("TRUST_SELFTEST_CHILD_UNPROVEN", e)
	}
	actual, e := windows.GetSecurityInfo(directoryHandle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if e != nil || !trustRevokeSecurityMatches(actual, sd) {
		return result, fmt.Errorf("TRUST_SELFTEST_CHILD_SECURITY_UNPROVEN")
	}
	source := filepath.Join(dir, "source.dummy")
	occupied := filepath.Join(dir, "occupied.dummy")
	stage := filepath.Join(dir, "staged.dummy")
	final := filepath.Join(dir, "final.dummy")
	m := trustRevokeMetadata{Version: 1, Stage: "synthetic_native_selftest", OriginalLeaf: "no-pairing-material", BackupLeaf: "no-pairing-material"}
	if e = trustRevokeWriteMetadata(source, m); e != nil {
		return result, e
	}
	if e = trustRevokeWriteMetadata(occupied, m); e != nil {
		return result, e
	}
	occupiedInfo, e := trustRevokeMetadataInfo(occupied)
	if e != nil {
		return result, e
	}
	var original windows.ByHandleFileInformation
	recordHandle, original, e = trustRevokeOpenRecord(source)
	if e != nil {
		return result, e
	}
	closed = false
	if e = trustRevokeRenameHandle(recordHandle, occupied); e == nil {
		return result, fmt.Errorf("TRUST_SELFTEST_OVERWROTE_EXISTING_FILE")
	}
	observedSource, se := trustRevokeMetadataInfo(source)
	observedOccupied, oe := trustRevokeMetadataInfo(occupied)
	if se != nil || oe != nil || !trustRevokeSameFile(original, observedSource) || !trustRevokeSameFile(occupiedInfo, observedOccupied) {
		return result, fmt.Errorf("TRUST_SELFTEST_NO_OVERWRITE_READBACK_FAILED")
	}
	result.NoOverwriteVerified = true
	if e = trustRevokeRenameHandle(recordHandle, stage); e != nil {
		return result, e
	}
	if e = trustRevokeProtectFile(recordHandle); e != nil {
		return result, e
	}
	if e = trustRevokeCloseAndDurableMove(recordHandle, &closed, stage, final); e != nil {
		return result, e
	}
	result.DurableFinalMoveVerified = true
	if e = trustRevokeVerifyBackup(final, original); e != nil {
		return result, e
	}
	result.FileIdentityVerified = true
	result.ProtectedOwnerACLVerified = true
	if _, e = trustRevokeAttributes(source); !errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
		return result, fmt.Errorf("TRUST_SELFTEST_ORIGINAL_ABSENCE_FAILED")
	}
	if _, e = trustRevokeAttributes(stage); !errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
		return result, fmt.Errorf("TRUST_SELFTEST_STAGE_ABSENCE_FAILED")
	}
	result.OriginalAbsentVerified = true
	link := filepath.Join(dir, "reparse.dummy")
	linkPtr, _ := windows.UTF16PtrFromString(link)
	targetPtr, _ := windows.UTF16PtrFromString(occupied)
	e = windows.CreateSymbolicLink(linkPtr, targetPtr, 2)
	if errors.Is(e, windows.ERROR_INVALID_PARAMETER) {
		e = windows.CreateSymbolicLink(linkPtr, targetPtr, 0)
	}
	if e != nil {
		result.Code = "INCOMPLETE"
		return result, trustRevokeSafeError("TRUST_SELFTEST_REPARSE_CREATION_UNAVAILABLE", e)
	}
	attrs, e := trustRevokeAttributes(link)
	if e != nil || attrs.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return result, fmt.Errorf("TRUST_SELFTEST_REPARSE_NATIVE_METADATA_UNPROVEN")
	}
	lh, _, le := trustRevokeOpenRecord(link)
	if le == nil {
		windows.CloseHandle(lh)
		return result, fmt.Errorf("TRUST_SELFTEST_REPARSE_NOT_REFUSED")
	}
	if le.Error() != "TRUST_RECORD_HANDLE_UNVERIFIED" {
		return result, fmt.Errorf("TRUST_SELFTEST_REPARSE_REFUSAL_UNATTRIBUTED")
	}
	result.ReparseRefusalVerified = true
	result.Code = "PASSED"
	return result, nil
}

func trustRevokeMetadataInfo(path string) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	ptr, _ := windows.UTF16PtrFromString(path)
	h, e := windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return info, trustRevokeSafeError("TRUST_SELFTEST_INFO_OPEN_FAILED", e)
	}
	defer windows.CloseHandle(h)
	if e = windows.GetFileInformationByHandle(h, &info); e != nil {
		return info, trustRevokeSafeError("TRUST_SELFTEST_INFO_READ_FAILED", e)
	}
	return info, nil
}
