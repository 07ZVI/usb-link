package connectioninstall

import (
	"fmt"
	"strings"
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
	return "smb://10.6.9.1/" + name
}

func selectNativeShareName(id string, used map[string]string) string {
	for name, owner := range used {
		if owner == id {
			return name
		}
	}
	name := nativeShareName(id)
	for other, owner := range used {
		if strings.EqualFold(other, name) && owner != id {
			return "USB-" + id
		}
	}
	return name
}

func validNativeShareName(id, name string) bool {
	return name == nativeShareName(id) || name == "USB-"+id || name == "USB-Link-"+id
}

// Never assume a name absent from our receipt is absent from Windows.
func availableNativeShareName(id string, used map[string]string, free func(string) (bool, error)) (string, error) {
	for _, name := range []string{selectNativeShareName(id, used), "USB-" + id, "USB-Link-" + id} {
		blocked := false
		for other, owner := range used {
			if strings.EqualFold(other, name) && owner != id {
				blocked = true
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
	return "", fmt.Errorf("NATIVE_SMB_NAME_CONFLICT: 所有候選名稱已由 Windows 使用")
}
