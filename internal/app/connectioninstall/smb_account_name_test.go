package connectioninstall

import (
	"strings"
	"testing"
)

func TestSMBAccountNamesAreLocalUnicodeSAMNames(t *testing.T) {
	for _, name := range []string{"USBLinkShare", "共享帳戶", "usb link", strings.Repeat("a", 20), strings.Repeat("😀", 10)} {
		if err := ValidateSMBAccountName(name); err != nil {
			t.Fatal("valid name rejected", name, err)
		}
	}
	for _, name := range []string{"", " . ", "..", ".", "share.", " share", "share ", "DOMAIN\\share", "share@domain", "share/dir", "share:445", "share\x00", "share\n", "share\xff", strings.Repeat("a", 21), strings.Repeat("😀", 11)} {
		if err := ValidateSMBAccountName(name); err == nil {
			t.Fatal("unsafe name accepted", name)
		}
	}
}
