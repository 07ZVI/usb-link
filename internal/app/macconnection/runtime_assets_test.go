package macconnection

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealUpgradePayloadKeepsLegacyAndReusesVerifiedRuntime(t *testing.T) {
	payload, manifest, hash, _ := concurrentRuntimeFixture(t)
	oldBytes := bytes.NewBufferString("legacy first party runtime fixture")
	parent := t.TempDir()
	oldDir := filepath.Join(parent, "mac-runtime-v4")
	os.Mkdir(oldDir, 0700)
	oldPath := filepath.Join(oldDir, "suhang-usbnet.exe")
	os.WriteFile(oldPath, oldBytes.Bytes(), 0600)
	dir, e := unpackRuntime(parent, payload, manifest, hash)
	if e != nil {
		t.Fatal(e)
	}
	if dir == oldDir {
		t.Fatal("new executable reuses old runtime directory")
	}
	got, e := os.ReadFile(oldPath)
	if e != nil || !bytes.Equal(got, oldBytes.Bytes()) {
		t.Fatal("legacy runtime changed")
	}
	again, e := unpackRuntime(parent, payload, manifest, hash)
	if e != nil || again != dir {
		t.Fatalf("verified runtime not reusable: %v", e)
	}
	names, e := recoveryRuntimeNames(parent)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(strings.Join(names, "|"), filepath.Base(dir)) || !strings.Contains(strings.Join(names, "|"), "mac-runtime-v4") {
		t.Fatal("recovery lost a runtime")
	}
	currentExe := filepath.Join(dir, "suhang-usbnet.exe")
	os.WriteFile(currentExe, []byte("modified"), 0600)
	if _, e = unpackRuntime(parent, payload, manifest, hash); e == nil || !strings.Contains(e.Error(), "suhang-usbnet.exe") {
		t.Fatalf("modified runtime not rejected with filename: %v", e)
	}
	got, _ = os.ReadFile(currentExe)
	if string(got) != "modified" {
		t.Fatal("unverified file overwritten")
	}
	var m map[string]any
	json.Unmarshal(manifest, &m)
	m["payload_sha256"] = strings.Repeat("0", 64)
	invalid, _ := json.Marshal(m)
	if _, e = unpackRuntime(t.TempDir(), payload, invalid, hash); e == nil {
		t.Fatal("invalid embedded manifest accepted")
	}
}
