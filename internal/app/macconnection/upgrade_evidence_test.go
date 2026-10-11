package macconnection

import (
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/diagnostics/logfile"
	"testing"
)

func TestUpgradeEvidenceSurvivesInstallerLogRotation(t *testing.T) {
	d := t.TempDir()
	body := []byte(`{"version":"candidate","stage":"gateway","error":"failed"}`)
	if e := appendUpgradeEvidence(d, body); e != nil {
		t.Fatal(e)
	}
	f, e := logfile.Open(filepath.Join(d, "installer.log"), 1024)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write([]byte(strings.Repeat("a", 900))); e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write([]byte(strings.Repeat("b", 200))); e != nil {
		t.Fatal(e)
	}
	f.Close()
	b, e := os.ReadFile(filepath.Join(d, "service.log"))
	if e != nil || !strings.Contains(string(b), string(body)) {
		t.Fatalf("evidence lost after restart log rotation: %v", e)
	}
}
func TestUpgradeEvidenceRejectsRedirectedOrOversizedLog(t *testing.T) {
	d := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("unchanged"), 0600)
	if e := os.Symlink(outside, filepath.Join(d, "service.log")); e != nil {
		t.Fatal(e)
	}
	if appendUpgradeEvidence(d, []byte("body")) == nil {
		t.Fatal("redirect accepted")
	}
	if appendUpgradeEvidence(t.TempDir(), make([]byte, 8193)) == nil {
		t.Fatal("oversized accepted")
	}
	b, _ := os.ReadFile(outside)
	if string(b) != "unchanged" {
		t.Fatal("outside log changed")
	}
}
