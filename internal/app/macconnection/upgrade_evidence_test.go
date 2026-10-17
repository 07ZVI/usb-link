package macconnection

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/diagnostics/logfile"
	"suhang/usbnet/internal/transport/ncm"
	"testing"
	"time"
)

func TestMaximumIPadEvidenceRowsSurviveTailAndDiagnosticTransport(t *testing.T) {
	maximumRow := func(section string) []byte {
		prefix := `{"core_version":"test","` + section + `":{"fixture":"`
		suffix := `"}}`
		remaining := 8192 - len(prefix) - len(suffix)
		body := []byte(prefix + strings.Repeat(`\"`, remaining/2) + strings.Repeat("x", remaining%2) + suffix)
		if len(body) != 8192 || !json.Valid(body) {
			t.Fatal("invalid maximum evidence fixture")
		}
		return body
	}
	connection := maximumRow("ipad_connection")
	network := maximumRow("ipad_runtime_network")
	trust := maximumRow("ipad_trust_timeline")
	timing := maximumRow("connection_timing")
	photo := maximumRow("photo_isolation")
	for _, installerPresent := range []bool{false, true} {
		name := "service-only"
		if installerPresent {
			name = "escaped-old-logs"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			// Include all five independent sections and an unrelated maximum row.
			if err := os.WriteFile(filepath.Join(dir, "service.log"), []byte(strings.Repeat("old", 24000)+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			for _, row := range [][]byte{connection, network, trust, timing, photo, maximumRow("stage")} {
				if err := appendUpgradeEvidence(dir, row); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"installer.log", "usbnet-bridge.log"} {
				if name == "installer.log" && !installerPresent {
					continue
				}
				// 64 KiB of control characters expands to 384 KiB in JSON.
				if err := os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte{0}, 64*1024), 0600); err != nil {
					t.Fatal(err)
				}
			}
			nonce := strings.Repeat("a", 32)
			payload, err := logfile.MarshalDiagnosticSnapshot(map[string]any{"version": "test", "nonce": nonce}, logfile.ReadDiagnosticTails(dir))
			if err != nil || len(payload) > 256*1024 {
				t.Fatalf("escaped payload exceeded transfer bound: %d %v", len(payload), err)
			}
			frames, err := ncm.DiagnosticFrames(payload, nonce, [6]byte{2, 3, 4, 5, 6, 7})
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(payload)
			var received []byte
			for index, frame := range frames {
				eth, err := ncm.ParseEthernet(frame)
				if err != nil || len(frame) > 1514 || len(eth.Payload) < 28 {
					t.Fatal("invalid diagnostic frame", err)
				}
				end := int(binary.BigEndian.Uint16(eth.Payload[2:]))
				var chunk struct {
					Nonce string `json:"nonce"`
					Index int    `json:"index"`
					Total int    `json:"total"`
					SHA   string `json:"sha256"`
					Data  string `json:"data"`
				}
				if err := json.Unmarshal(eth.Payload[28:end], &chunk); err != nil {
					t.Fatal(err)
				}
				if chunk.Nonce != nonce || chunk.Index != index || chunk.Total != len(frames) || chunk.SHA != hex.EncodeToString(digest[:]) {
					t.Fatal("diagnostic transfer identity changed")
				}
				part, err := base64.StdEncoding.DecodeString(chunk.Data)
				if err != nil {
					t.Fatal(err)
				}
				received = append(received, part...)
			}
			if !bytes.Equal(received, payload) {
				t.Fatal("diagnostic payload changed during transfer")
			}
			var result struct {
				Logs      map[string]string `json:"logs"`
				Truncated map[string]bool   `json:"log_prefixes_omitted_for_transport"`
			}
			if err := json.Unmarshal(received, &result); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(result.Logs["installer.log"], "USB_LINK_UPGRADE_EVIDENCE "+string(connection)+"\n") ||
				!strings.Contains(result.Logs["installer.log"], "USB_LINK_UPGRADE_EVIDENCE "+string(network)+"\n") ||
				!strings.Contains(result.Logs["installer.log"], "USB_LINK_UPGRADE_EVIDENCE "+string(trust)+"\n") ||
				!strings.Contains(result.Logs["installer.log"], "USB_LINK_UPGRADE_EVIDENCE "+string(timing)+"\n") ||
				!strings.Contains(result.Logs["installer.log"], "USB_LINK_UPGRADE_EVIDENCE "+string(photo)+"\n") || len(result.Truncated) == 0 {
				t.Fatal("latest complete connection/network evidence lost or truncation unreported")
			}
		})
	}
}

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

func TestConnectionEvidenceWritesOnlyChangesAndRetriesFailedWrite(t *testing.T) {
	dir := t.TempDir()
	previous := connectionEvidenceLogState{}
	now := time.Now()
	row := map[string]any{"core_version": "test", "ipad_connection": map[string]any{"state": "offline"}}
	if err := appendChangedConnectionEvidence(dir, row, &previous, now); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "service.log")
	first, _ := os.ReadFile(path)
	if err := appendChangedConnectionEvidence(dir, row, &previous, now.Add(29*time.Second)); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if string(first) != string(second) {
		t.Fatal("unchanged snapshot wrote another log entry")
	}
	if err := appendChangedConnectionEvidence(dir, row, &previous, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	refreshed, _ := os.ReadFile(path)
	if strings.Count(string(refreshed), "USB_LINK_UPGRADE_EVIDENCE") != 2 {
		t.Fatal("stable snapshot did not refresh at 30 seconds")
	}
	row["ipad_connection"] = map[string]any{"state": "connected"}
	failedDir := filepath.Join(dir, "missing", "child")
	beforeFailure := previous
	if err := appendChangedConnectionEvidence(failedDir, row, &previous, now.Add(35*time.Second)); err == nil || previous != beforeFailure {
		t.Fatal("failed write consumed the pending change", err)
	}
	if err := appendChangedConnectionEvidence(dir, row, &previous, now.Add(40*time.Second)); err != nil || previous == beforeFailure {
		t.Fatal("changed snapshot did not retry", err)
	}
	last := previous
	if err := appendChangedConnectionEvidence(dir, strings.Repeat("x", 8193), &previous, now.Add(45*time.Second)); err == nil || previous != last {
		t.Fatal("oversized snapshot accepted or marked written", err)
	}
}
