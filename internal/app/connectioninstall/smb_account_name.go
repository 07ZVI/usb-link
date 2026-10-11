package connectioninstall

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// A local SAM account name, never a DOMAIN\user, path or group expression.
func ValidateSMBAccountName(name string) error {
	if !utf8.ValidString(name) || name == "" || strings.TrimSpace(name) != name || strings.Trim(name, ".") == "" || strings.HasSuffix(name, ".") || len(utf16.Encode([]rune(name))) > 20 || strings.ContainsAny(name, `"/\[]:;|=,+*?<>@`) {
		return fmt.Errorf("帳戶名稱需為 1–20 個 UTF-16 字元，不能是網域名稱、路徑，或包含 Windows 禁用的符號。")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("帳戶名稱不能包含控制字元。")
		}
	}
	return nil
}
