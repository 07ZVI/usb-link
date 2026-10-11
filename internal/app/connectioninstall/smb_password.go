package connectioninstall

import (
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Validate before any existing share is interrupted. Never include the value in errors.
func ValidateSMBPassword(text string) error {
	if !utf8.ValidString(text) || strings.ContainsRune(text, 0) || utf8.RuneCountInString(text) < 8 || len(utf16.Encode([]rune(text))) > 256 {
		return fmt.Errorf("密碼至少 8 個字元，最多 256 個 UTF-16 字元，不能包含空字元。")
	}
	return nil
}
