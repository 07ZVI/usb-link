package installer

import (
	"strings"
	"testing"
)

func TestExtractionPathUsesProfileEscaping(t *testing.T) {
	// Include backslash-n/t/b and spaces, which broke the old quoted INI.
	dir := `C:\Users\AVA\AppData\Local\Suhang\USBProbe\0.2.2\driver-20261001-170000-mi00`
	ini, err := ZadigConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := `default_dir="C:\\Users\\AVA\\AppData\\Local\\Suhang\\USBProbe\\0.2.2\\driver-20261001-170000-mi00"` + "\n"
	if !strings.Contains(ini, want) {
		t.Fatalf("wrong profile path: %s", ini)
	}
	for _, line := range []string{"extract_only=true\n", "exit_on_success=false\n", "default_driver=0\n", "include_hubs=false\n"} {
		if !strings.Contains(ini, line) {
			t.Fatal("lost required setting", line)
		}
	}
	ini, err = ZadigConfig(`C:\資料 空間\ncm\tools\backup\"quoted"`)
	if err != nil || !strings.Contains(ini, `default_dir="C:\\資料 空間\\ncm\\tools\\backup\\\"quoted\""`) {
		t.Fatalf("quote/unicode escaping: %q %v", ini, err)
	}
}

func TestExtractionConfigRejectsInjectedLines(t *testing.T) {
	for _, dir := range []string{"", "C:\\x\nextract_only=false", "C:\\x\r[driver]", "C:\\x\x00tail", "C:\\x\tfile"} {
		if _, err := ZadigConfig(dir); err == nil {
			t.Fatal("accepted invalid path", dir)
		}
	}
}
