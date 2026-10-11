package connectioninstall

import (
	"strings"
	"testing"
)

func TestSMBPasswordInputIsBoundedAndErrorsDoNotExposeSecrets(t *testing.T) {
	for _, text := range []string{"aA!12345", " 中文密碼測試八字 ", strings.Repeat("😀", 128)} {
		if e := ValidateSMBPassword(text); e != nil {
			t.Fatal("valid password rejected")
		}
	}
	for _, text := range []string{"", "aA!1234", "aA!12345\x00secret", strings.Repeat("😀", 129), "aA!12345\xff"} {
		e := ValidateSMBPassword(text)
		if e == nil {
			t.Fatal("invalid password accepted")
		}
		if text != "" && strings.Contains(e.Error(), text) {
			t.Fatal("error exposes secret")
		}
	}
}
