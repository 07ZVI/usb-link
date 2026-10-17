package connectioninstall

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf16"
)

// Registered users browse the server to choose a share. Guest clients can use
// nativeSMBConnectURL when server enumeration is denied by Windows policy.
const NativeSMBServerURL = "smb://10.6.9.1/"

func nativeShareName(id string) string {
	if id == "000000000000000000000001" {
		return "USB"
	}
	if len(id) < 8 {
		return ""
	}
	return "USB-" + id[:8]
}

// Use a share that Windows has read back as ours. Server-root browsing is a
// separate permission check and can fail for Guest even when the share works.
func nativeSMBConnectURL(sharedNames []string) string {
	name := ""
	for _, candidate := range sharedNames {
		if candidate == "USB" {
			return "smb://10.6.9.1/USB"
		}
		if name == "" || candidate < name {
			name = candidate
		}
	}
	if name == "" {
		return "smb://10.6.9.1"
	}
	return nativeFolderSMBURL(name)
}

// Keep legacy names valid for existing protected ownership receipts.
func legacyNativeShareName(id, name string) bool {
	return name == nativeShareName(id) || name == "USB-"+id || name == "USB-Link-"+id
}

func folderShareName(path string) string {
	parts := strings.Split(strings.TrimRight(strings.ReplaceAll(path, `\`, "/"), "/"), "/")
	name := strings.Map(func(r rune) rune {
		if r < 32 || strings.ContainsRune(`"/\[]:;|=,+*?<>`, r) {
			return '_'
		}
		return r
	}, parts[len(parts)-1])
	name = strings.Trim(name, " .")
	if name == "" {
		name = "Shared"
	}
	// Windows share names are limited to 80 UTF-16 code units.
	for len(utf16.Encode([]rune(name))) > 80 {
		r := []rune(name)
		name = string(r[:len(r)-1])
	}
	if strings.HasSuffix(name, "$") {
		name = strings.TrimSuffix(name, "$") + "_"
	}
	return name
}

func nativeFolderSMBURL(name string) string { return "smb://10.6.9.1/" + url.PathEscape(name) }

func validNativeShareName(id, name string, path ...string) bool {
	if legacyNativeShareName(id, name) {
		return true
	}
	if len(path) == 0 {
		return false
	}
	return validFolderNativeShareName(name, path[0])
}

func validFolderNativeShareName(name, path string) bool {
	base := folderShareName(path)
	for i := 1; i <= 100; i++ {
		if name == numberedShareName(base, i) {
			return true
		}
	}
	return false
}

func numberedShareName(base string, n int) string {
	if n == 1 {
		return base
	}
	suffix := fmt.Sprintf(" (%d)", n)
	for len(utf16.Encode([]rune(base+suffix))) > 80 {
		r := []rune(base)
		base = string(r[:len(r)-1])
	}
	return base + suffix
}

// Query Windows as well as our receipts; never overwrite an unrelated share.
func availableNativeShareName(id, path string, used map[string]string, free func(string) (bool, error)) (string, error) {
	base := folderShareName(path)
	for i := 1; i <= 100; i++ {
		name := numberedShareName(base, i)
		blocked := false
		for other, owner := range used {
			if strings.EqualFold(other, name) && owner != id {
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}
		ok, err := free(name)
		if err != nil {
			return "", err
		}
		if ok {
			return name, nil
		}
	}
	return "", fmt.Errorf("NATIVE_SMB_NAME_CONFLICT: 資料夾 %s 的同名共享過多", base)
}
