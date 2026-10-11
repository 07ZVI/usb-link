//go:build windows && amd64

package ipadncm

import (
	"errors"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/app/connectioninstall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Explicit experiment only. File attributes cannot return pairing contents.
// Never enumerate directories, open files, or send a usbmux/lockdown request.
type UnpairedFileAttributeObservation struct {
	Scope       string `json:"scope"`
	Readable    bool   `json:"readable"`
	Present     bool   `json:"present"`
	Directory   bool   `json:"directory"`
	Reparse     bool   `json:"reparse"`
	NativeError uint32 `json:"native_error,omitempty"`
}
type UnpairedPairMetadataReadback struct {
	Metadata   UnpairedPairMetadata               `json:"metadata"`
	Attributes []UnpairedFileAttributeObservation `json:"attributes"`
	Error      string                             `json:"error,omitempty"`
}

func InspectUnpairedPairMetadataReadback(before Snapshot) UnpairedPairMetadataReadback {
	var result UnpairedPairMetadataReadback
	value, err := inspectUnpairedPairMetadata(before, &result.Attributes)
	result.Metadata = value
	if err != nil {
		result.Error = err.Error()
	}
	return result
}
func InspectUnpairedPairMetadata(before Snapshot) (UnpairedPairMetadata, error) {
	return inspectUnpairedPairMetadata(before, nil)
}
func inspectUnpairedPairMetadata(before Snapshot, observations *[]UnpairedFileAttributeObservation) (UnpairedPairMetadata, error) {
	var out UnpairedPairMetadata
	if !networkOnlyUSBEligible(before) || !descriptorAttachment(before).same(descriptorAttachment(Inspect())) {
		return out, errors.New("UNPAIRED_EXACT_USB_IDENTITY_UNAVAILABLE")
	}
	serial := before.Devices[0].usbSerial
	root := exactIPadRoot(before)
	if !usbDescriptorRootMatches(root, serial) {
		return out, errors.New("UNPAIRED_EXACT_USB_IDENTITY_UNAVAILABLE")
	}
	leaves := unpairedPairLeaves(serial)
	if len(leaves) == 0 {
		return out, errors.New("UNPAIRED_PAIR_FILENAME_UNPROVEN")
	}
	out.USBSerialSHA256 = before.Devices[0].USBSerialSHA256
	out.USBSerialSuffix = strings.ToLower(serial[len(serial)-4:])
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return out, errors.New("UNPAIRED_PROGRAM_DATA_UNAVAILABLE")
	}
	if err := verifyUnpairedOriginalAbsence(base, leaves, observations); err != nil {
		return out, err
	}
	out.OriginalAbsent = true
	desktop, err := connectioninstall.UserKnownFolderPath(windows.FOLDERID_Desktop, 0)
	if err != nil {
		return out, errors.New("UNPAIRED_DESKTOP_UNAVAILABLE")
	}
	a, e := observeUnpairedAttributes(desktop, "known_folder_desktop", observations)
	if e != nil || a.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || a.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return out, errors.New("UNPAIRED_DESKTOP_DIRECTORY_UNVERIFIED")
	}
	backupCount := 0
	// Both names remain descriptor-derived. Lockdown is one fixed backup
	// child chosen by the user; this is not an arbitrary path or enumeration.
	for _, folder := range []string{"", "Lockdown"} {
		backupBase, scope := desktop, "desktop_exact_backup"
		if folder != "" {
			backupBase = filepath.Join(desktop, folder)
			a, e := observeUnpairedAttributes(backupBase, "desktop_lockdown_backup_dir", observations)
			if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
				continue
			}
			if e != nil || a.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || a.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
				return out, errors.New("UNPAIRED_DESKTOP_BACKUP_DIRECTORY_UNVERIFIED")
			}
			scope = "desktop_lockdown_exact_backup"
		}
		for _, leaf := range leaves {
			a, e := observeUnpairedAttributes(filepath.Join(backupBase, leaf), scope, observations)
			if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
				continue
			}
			if e != nil {
				return out, errors.New("UNPAIRED_DESKTOP_METADATA_UNREADABLE")
			}
			if a.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
				return out, errors.New("UNPAIRED_BACKUP_NOT_REGULAR_FILE")
			}
			size := uint64(a.FileSizeHigh)<<32 | uint64(a.FileSizeLow)
			if size == 0 || size > 512*1024 {
				return out, errors.New("UNPAIRED_BACKUP_SIZE_UNEXPECTED")
			}
			backupCount++
		}
	}
	out.BackupPresent = backupCount == 1
	if !out.BackupPresent {
		return out, errors.New("UNPAIRED_EXACT_DESKTOP_BACKUP_UNPROVEN")
	}
	if !descriptorAttachment(before).same(descriptorAttachment(Inspect())) {
		return out, errors.New("UNPAIRED_USB_CHANGED_DURING_METADATA_CHECK")
	}
	// A bounded second complete observation must still prove the store/leaf
	// absent. Unknown errors and reparse paths never become absence evidence.
	if err := verifyUnpairedOriginalAbsence(base, leaves, observations); err != nil {
		out.OriginalAbsent = false
		return out, err
	}
	return out, nil
}

func unpairedAttributes(path string) (windows.Win32FileAttributeData, error) {
	var a windows.Win32FileAttributeData
	p, err := windows.UTF16PtrFromString(path)
	if err == nil {
		err = windows.GetFileAttributesEx(p, 0, (*byte)(unsafe.Pointer(&a)))
	}
	return a, err
}

func verifyUnpairedOriginalAbsence(base string, leaves []string, observations *[]UnpairedFileAttributeObservation) error {
	for i, part := range []string{"", "Apple", "Lockdown"} {
		base = filepath.Join(base, part)
		scopes := []string{"program_data", "apple_parent", "lockdown_store"}
		a, err := observeUnpairedAttributes(base, scopes[i], observations)
		if err != nil || a.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || a.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("UNPAIRED_ORIGINAL_STORE_UNVERIFIED")
		}
	}
	for _, leaf := range leaves {
		_, err := observeUnpairedAttributes(filepath.Join(base, leaf), "original_exact_leaf", observations)
		if err == nil {
			return errors.New("UNPAIRED_ORIGINAL_PAIR_FILE_PRESENT")
		}
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return errors.New("UNPAIRED_ORIGINAL_FILE_METADATA_UNREADABLE")
		}
	}
	return nil
}
func observeUnpairedAttributes(path, scope string, observations *[]UnpairedFileAttributeObservation) (windows.Win32FileAttributeData, error) {
	a, err := unpairedAttributes(path)
	if observations != nil && len(*observations) < 16 {
		o := UnpairedFileAttributeObservation{Scope: scope, Readable: err == nil || errors.Is(err, windows.ERROR_FILE_NOT_FOUND), Present: err == nil, Directory: a.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0, Reparse: a.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0}
		var native windows.Errno
		if errors.As(err, &native) {
			o.NativeError = uint32(native)
		}
		*observations = append(*observations, o)
	}
	return a, err
}
